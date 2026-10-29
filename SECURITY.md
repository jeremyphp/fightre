# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately: open a GitHub security
advisory (preferred) or email the maintainers listed in `pyproject.toml`.

Include: affected version, a minimal reproduction, and the impact you believe it
has. We aim to acknowledge within 72 hours and to ship a fix or a documented
mitigation within 30 days for high-severity issues.

Please do not open a public issue for an unfixed bypass.

## Scope

In scope:

- ways to make the guard allow a request that should be challenged, deceived or
  blocked (e.g. forging an attestation, replaying a signature, evading the
  canary registry);
- denial of service caused by FightRE itself (unbounded memory, unbounded
  tarpit delay, algorithmic complexity in header parsing);
- leakage of client identifiers into logs;
- dependency or packaging compromise.

Out of scope (by design, documented in `docs/THREAT-MODEL.md`):

- "I can still reverse engineer the client if I control the device." True, and
  expected: FightRE raises cost, it does not provide DRM.
- "Attestation can be replayed within its TTL." Expected; the TTL is a
  configuration knob, not a security boundary.
- Detection of a specific commercial stealth tool. Signal weights may be tuned,
  but no detector is guaranteed.

## Responsible use

FightRE is a defensive component for software you own or operate. It must not be
used to:

- interfere with another party's software, tooling or forensic evidence;
- obstruct authorised security research, incident response or interoperability
  testing;
- track end users beyond the request lifecycle.

Misuse is contrary to the project's intent and outside the support boundary.
