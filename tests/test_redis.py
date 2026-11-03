"""RESP client and Redis-backed store tests (against an in-process fake server)."""

from __future__ import annotations

import unittest

from fightre.canary import CanaryRegistry
from fightre.challenge import NonceStore
from fightre.config import Config
from fightre.redis import RedisClient, RedisServerError
from fightre.stores import (
    HybridCanaryRegistry,
    RedisCanaryStore,
    RedisNonceStore,
    RedisRateLimiter,
    RedisSequenceTracker,
    Stores,
    build_stores,
)
from tests.fake_redis import FakeRedisServer


class RedisClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = FakeRedisServer().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def setUp(self) -> None:
        self.client = RedisClient("127.0.0.1", self.server.port, timeout=2.0, prefix="t")

    def tearDown(self) -> None:
        self.client.close()

    def test_ping(self) -> None:
        self.assertTrue(self.client.ping())

    def test_set_get(self) -> None:
        self.assertEqual(self.client.command("SET", "k", "v"), "OK")
        self.assertEqual(self.client.command("GET", "k"), b"v")

    def test_set_nx(self) -> None:
        self.assertEqual(self.client.command("SET", "nx", "1", "NX", "EX", "10"), "OK")
        self.assertIsNone(self.client.command("SET", "nx", "2", "NX", "EX", "10"))

    def test_increment_and_sets(self) -> None:
        self.assertEqual(self.client.command("INCR", "counter"), 1)
        self.assertEqual(self.client.command("INCR", "counter"), 2)
        self.assertEqual(self.client.command("SADD", "s", "a"), 1)
        self.assertEqual(self.client.command("SADD", "s", "a"), 0)
        self.assertEqual(self.client.command("SCARD", "s"), 1)

    def test_server_error_is_raised_but_connection_survives(self) -> None:
        with self.assertRaises(RedisServerError):
            self.client.command("NOPE")
        self.assertTrue(self.client.ping())

    def test_key_prefix(self) -> None:
        self.assertEqual(self.client.key("nonce", "abc"), "t:nonce:abc")


class RedisStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = FakeRedisServer().start()
        self.client = RedisClient("127.0.0.1", self.server.port, timeout=2.0, prefix="w1")

    def tearDown(self) -> None:
        self.client.close()
        self.server.stop()

    def test_nonce_store_replay_across_workers(self) -> None:
        store = RedisNonceStore(self.client)
        self.assertTrue(store.consume("jti-1", ttl=60))
        # A second worker with its own client sees the same key.
        other = RedisClient("127.0.0.1", self.server.port, timeout=2.0, prefix="w1")
        try:
            self.assertFalse(RedisNonceStore(other).consume("jti-1", ttl=60))
        finally:
            other.close()

    def test_rate_limiter_blocks_after_limit(self) -> None:
        limiter = RedisRateLimiter(self.client, limit=3, window_seconds=60)
        results = [limiter.allow("203.0.113.1")[0] for _ in range(5)]
        self.assertEqual(results, [True, True, True, False, False])
        allowed, retry_after = limiter.allow("203.0.113.1")
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)

    def test_rate_limiter_separates_identities(self) -> None:
        limiter = RedisRateLimiter(self.client, limit=1, window_seconds=60)
        self.assertTrue(limiter.allow("a")[0])
        self.assertFalse(limiter.allow("a")[0])
        self.assertTrue(limiter.allow("b")[0])

    def test_canary_cross_worker_attribution(self) -> None:
        local_a = CanaryRegistry()
        store_a = HybridCanaryRegistry(local_a, RedisCanaryStore(self.client))
        canary = store_a.issue("tenant-7", {"path": "/x"})

        local_b = CanaryRegistry()  # worker B never issued this canary
        store_b = HybridCanaryRegistry(local_b, RedisCanaryStore(self.client))
        found = store_b.find(f"leak: {canary.token}")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].owner, "tenant-7")
        self.assertEqual(found[0].meta["path"], "/x")

    def test_sequence_tracker(self) -> None:
        tracker = RedisSequenceTracker(self.client, window_seconds=60, distinct=3)
        hits = [tracker.hit("ip", f"/p{i}", now=1000.0) for i in range(4)]
        self.assertEqual(hits, [False, False, True, False])


class FallbackTests(unittest.TestCase):
    def test_unreachable_redis_falls_back_to_memory(self) -> None:
        client = RedisClient("127.0.0.1", 1, timeout=0.2, prefix="down")
        memory = CanaryRegistry()
        nonce = RedisNonceStore(client, fallback=NonceStore())
        self.assertTrue(nonce.consume("k", ttl=30))
        self.assertFalse(nonce.consume("k", ttl=30))

        hybrid = HybridCanaryRegistry(memory, RedisCanaryStore(client))
        canary = hybrid.issue("owner")
        self.assertEqual(hybrid.find(canary.token)[0].owner, "owner")
        self.assertGreaterEqual(client.errors, 1)
        client.close()


class FactoryTests(unittest.TestCase):
    def test_memory_by_default(self) -> None:
        stores = build_stores(Config(), "secret")
        self.assertEqual(stores.backend, "memory")
        self.assertTrue(stores.health()["ok"])

    def test_redis_when_enabled(self) -> None:
        server = FakeRedisServer().start()
        try:
            config = Config.from_dict(
                {"redis": {"enabled": True, "port": server.port, "timeout": 2.0}}
            )
            stores = build_stores(config, "secret")
            self.assertEqual(stores.backend, "redis")
            self.assertIsInstance(stores, Stores)
            health = stores.health()
            self.assertTrue(health["ok"])
            self.assertEqual(health["backend"], "redis")
            stores.client.close()
        finally:
            server.stop()


class GuardIntegrationTests(unittest.TestCase):
    """Prove the wiring: two Guard instances share replay defence and canaries."""

    def test_challenge_and_canary_shared_across_guards(self) -> None:
        from fightre.challenge import solve_pow
        from fightre.guard import Guard

        server = FakeRedisServer().start()
        workers = []
        try:
            config = Config.from_dict(
                {
                    "security": {"secret": "cluster-secret", "audit_path": ""},
                    "redis": {"enabled": True, "port": server.port, "timeout": 2.0},
                }
            )
            worker_a = Guard(config)
            worker_b = Guard(config)
            workers = [worker_a, worker_b]
            self.assertEqual(worker_a.stores.backend, "redis")

            issued = worker_a.issuer.issue("203.0.113.5")
            challenge = worker_a.issuer.verify(issued["token"])
            nonce = solve_pow(issued["jti"], issued["difficulty"])
            ok, _ = worker_a.issuer.check_solution(challenge, nonce)
            self.assertTrue(ok)
            # Worker B must reject the same solution: shared nonce store.
            ok_b, reason = worker_b.issuer.check_solution(challenge, nonce)
            self.assertFalse(ok_b)
            self.assertEqual(reason, "challenge already solved")

            # A canary issued by A is attributable by B.
            canary = worker_a.decoys.respond(worker_a.decoys.endpoints[0], "1.2.3.4")
            token = canary["keys"][0]["kid"]
            self.assertIsNotNone(worker_b.canaries.find(f"leak {token}"))
        finally:
            for worker in workers:
                worker.close()
            server.stop()


if __name__ == "__main__":
    unittest.main()
