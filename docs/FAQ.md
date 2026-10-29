# FAQ

## Does FightRE make my app impossible to reverse engineer?

No, and no tool does. If the code runs on hardware someone else controls, it can
be read. FightRE raises the cost per verified fact, removes the material that
makes analysis cheap (symbols, maps, schemas), and makes extracted data
attributable. Treat it as defence in depth, not as DRM.

## How is this different from a commercial anti-bot product?

- **Self-hosted and inspectable.** Every weight and threshold is in the repo.
- **Explainable.** Each decision lists the signals that produced it.
- **Zero dependencies.** One `pip install`, no agent, no vendor SDK.
- **Deception-first.** We prefer feeding an agent plausible false data over
  blocking it, because blocking teaches it to change.
- **Built for agentic tooling.** Schema poisoning, evidence contradiction and
  proof-of-work target LLM-driven pipelines specifically.

## Is serving fake data to scanners legal and ethical?

FightRE only fabricates responses from your own service to requests that hit
paths no legitimate client uses (unlinked honey endpoints, or an OpenAPI document
that is not load-bearing). It never modifies another party's software, and every
decoy credential is inert and registered. This is the same class of control as a
honeypot. If your jurisdiction or contracts require plain 403s, disable
`poison_enabled` and keep the rest.

## Will it break accessibility tools, old browsers or corporate proxies?

Challenge is preferred over block, and the bypass list exists for monitoring and
health checks. Still, heuristics produce false positives. Roll out in observe
mode first (`block: 101`), read the audit log, and tune weights against your own
traffic. Do not use root/jailbreak signals as an automatic account ban.

## Does the browser client work without JavaScript?

No. A client without JS never calls `/_fightre/attest`, so it carries a small
`client.missing_attestation` weight (16). That alone will not block a human; it
just means such clients are challenged earlier if other evidence appears.

## Do I need Redis?

Only for multiple workers. Attestation and signatures are stateless. Replay
defence, rate limits, path diversity and canary attribution are not; with
`redis.enabled` they become cluster-wide. Without Redis they are per process and
degrade to local state if the server is unreachable.

## Why Apache-2.0 and not MIT?

Apache-2.0 adds an explicit patent grant and a patent-retaliation clause, plus a
trademark clause. For a component embedded in commercial products that clarity is
worth the extra formality.

## Can I use it to protect a site I do not own?

No. It is for software and services you own or operate. Using it to obstruct
authorised research or someone else's tooling is outside the license's intent and
the project's ethics.

## Where do I start?

1. `fightre audit ./dist` and `fightre native ./dist` — remove free material.
2. Add the ASGI/WSGI middleware in observe mode.
3. Read `fightre explain audit.jsonl` after a week.
4. Turn on challenge, then deception, then blocks for hard signals only.
