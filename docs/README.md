# Documentation

Start here, then go as deep as you need.

| Document | What it answers |
| --- | --- |
| **[REA.md](REA.md)** | What REA is, how an agentic RE pipeline works, which seams are attackable, and what FightRE does at each stage. |
| **[THREAT-MODEL.md](THREAT-MODEL.md)** | Capability-by-capability mapping, trust boundaries, assumptions, non-goals. |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Request pipeline, scoring model, policy bands, state, failure modes, extension points. |
| **[DEPLOYMENT.md](DEPLOYMENT.md)** | Framework integration, config reference, edge fingerprints, Redis, rollout plan. |
| **[SIGNALS.md](SIGNALS.md)** | All 51 signals, weights and descriptions — generated from code. |
| **[FAQ.md](FAQ.md)** | Honest answers: DRM, legality, false positives, Redis, licensing. |
| **[../native/README.md](../native/README.md)** | Native binary audit, runtime self-check, Android/iOS guards, hardware attestation. |
| **[../SECURITY.md](../SECURITY.md)** | Reporting vulnerabilities, scope, responsible use. |
| **[../CONTRIBUTING.md](../CONTRIBUTING.md)** | Adding a detector or an adapter, test expectations. |

## Reading paths

- **Evaluating the project**: REA.md → README demo → THREAT-MODEL.md
- **Deploying it**: DEPLOYMENT.md → ARCHITECTURE.md → SIGNALS.md
- **Extending it**: ARCHITECTURE.md "Extending" → CONTRIBUTING.md
- **Shipping a desktop/mobile build**: native/README.md → manifest + selfcheck
