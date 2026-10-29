"""Protocol-layer header analysis tests."""

from __future__ import annotations

import unittest

from fightre import headers as hdr

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

CLEAN = {
    "host": "app.example.com",
    "user-agent": CHROME_UA,
    "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
    "accept": "text/html,application/xhtml+xml",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
}

CLEAN_ORDER = [
    ("Host", "app.example.com"),
    ("sec-ch-ua", '"Chromium";v="131", "Not_A Brand";v="24"'),
    ("sec-ch-ua-platform", '"Windows"'),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent", CHROME_UA),
    ("Accept", "text/html"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Language", "en-US,en;q=0.9"),
]


def names(found) -> set:
    return {s.name for s in found}


class HeaderTests(unittest.TestCase):
    def test_clean_browser_has_no_signals(self) -> None:
        self.assertEqual(hdr.analyze(CLEAN, CLEAN_ORDER), [])

    def test_bot_user_agent(self) -> None:
        found = hdr.analyze({"user-agent": "curl/8.5.0", "accept": "*/*"})
        self.assertIn("proto.bot_user_agent", names(found))

    def test_client_hint_version_mismatch(self) -> None:
        headers = dict(CLEAN)
        headers["sec-ch-ua"] = '"Chromium";v="120"'
        self.assertIn("proto.ua_client_hints_mismatch", names(hdr.analyze(headers)))

    def test_platform_mismatch(self) -> None:
        headers = dict(CLEAN)
        headers["sec-ch-ua-platform"] = '"macOS"'
        self.assertIn("proto.ua_client_hints_mismatch", names(hdr.analyze(headers)))

    def test_missing_fetch_metadata(self) -> None:
        headers = dict(CLEAN)
        del headers["sec-fetch-site"]
        self.assertIn("proto.missing_browser_headers", names(hdr.analyze(headers)))

    def test_smuggling_probe_is_critical(self) -> None:
        headers = {"user-agent": "x", "content-length": "5", "transfer-encoding": "chunked"}
        found = [s for s in hdr.analyze(headers) if s.name == "proto.smuggling_probe"]
        self.assertTrue(found and found[0].critical)

    def test_duplicate_singleton_header(self) -> None:
        pairs = [("Host", "a"), ("Host", "b"), ("User-Agent", CHROME_UA)]
        self.assertIn("proto.duplicate_header", names(hdr.analyze(CLEAN, pairs)))

    def test_header_order_anomaly(self) -> None:
        shuffled = list(reversed(CLEAN_ORDER))
        self.assertIn("proto.header_order_anomaly", names(hdr.analyze(CLEAN, shuffled)))

    def test_accept_encoding_mismatch(self) -> None:
        headers = dict(CLEAN)
        headers["accept-encoding"] = "gzip"
        self.assertIn("proto.accept_encoding_mismatch", names(hdr.analyze(headers)))


class HelperTests(unittest.TestCase):
    def test_ua_family(self) -> None:
        self.assertEqual(hdr.ua_family(CHROME_UA), "chrome")
        self.assertEqual(hdr.ua_family("Mozilla/5.0 Firefox/130.0"), "firefox")
        self.assertEqual(hdr.ua_family("curl/8.5.0"), "other")

    def test_chrome_major(self) -> None:
        self.assertEqual(hdr.chrome_major(CHROME_UA), 131)
        self.assertIsNone(hdr.chrome_major("curl/8.5.0"))

    def test_expected_platform(self) -> None:
        self.assertEqual(hdr.expected_platform(CHROME_UA), "Windows")
        self.assertEqual(hdr.expected_platform("Mozilla/5.0 (iPhone) Safari/604"), "iOS")

    def test_order_inversions(self) -> None:
        inversions, covered = hdr.order_inversions(CLEAN_ORDER, hdr.CHROME_ORDER)
        self.assertEqual(inversions, 0)
        self.assertGreaterEqual(covered, 6)

    def test_brand_majors(self) -> None:
        self.assertEqual(hdr.brand_majors('"Chromium";v="131", "Not_A Brand";v="24"'), [131, 24])


if __name__ == "__main__":
    unittest.main()
