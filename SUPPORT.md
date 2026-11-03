# Support

FightRE is Apache-2.0 and free to use. This page explains what help exists, what
response to expect, and where the boundary is between community support and paid
work.

## Before asking

Three documents answer most questions:

| Question | Read |
|---|---|
| Where do I start? | [QUICKSTART.md](QUICKSTART.md) |
| Why does it work this way? What can't it do? | [docs/DESIGN-RATIONALE.md](docs/DESIGN-RATIONALE.md) |
| Which signals fired and why? | [docs/SIGNALS.md](docs/SIGNALS.md) |
| How do I configure the edge / rollout? | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Is my use case supported? | [docs/FAQ.md](docs/FAQ.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) |

## Community support (free, best effort)

| Channel | Use it for | Expected response |
|---|---|---|
| [Discussions → Q&A](https://github.com/jeremyphp/fightre/discussions) | deployment questions, configuration, "is this normal?" | a few days |
| [Discussions → Bypass reports](https://github.com/jeremyphp/fightre/discussions) | "I defeated X", with a reproduction | reviewed promptly; published |
| [Issues](https://github.com/jeremyphp/fightre/issues) | reproducible defects, documentation errors | triaged when time allows |
| [Discussions → Show your setup](https://github.com/jeremyphp/fightre/discussions) | production deployments, numbers | welcomed |

There is no SLA on community channels. A question that arrives with a reproduction,
a version, and the relevant `mode` and config excerpt gets an answer far faster than
one that does not.

## Security reports (private)

Do **not** open a public issue for a bypass or vulnerability. Use the private
advisory flow described in [SECURITY.md](SECURITY.md). We aim to acknowledge within
72 hours and to publish a fixed release plus a note for anything that changes the
threat model.

## Commercial support

Available on request, for organisations that need a contractual relationship rather
than best effort. Typical scope:

- private deployment review (edge integration, fingerprint signing, rollout plan)
- signal weight tuning against your own traffic, with an observe-mode baseline
- custom detectors for your protocol or threat model
- integration work for a framework or gateway not covered by the adapters
- a support agreement with a response-time commitment

Open a Discussion in the repository with the `commercial` tag, or contact the
maintainer through the address in [SECURITY.md](SECURITY.md). No inquiry is a sales
call: state the environment and the problem, and you will get an assessment,
including "you do not need this".

## What is never charged for

- The software, in any form, for any use, including commercial.
- Bypass reports and their analysis.
- Security fixes. A fix for a reported bypass ships in the public release, always.

## What we will not do

- Guarantee that a given adversary cannot analyse your artifact. See
  [docs/DESIGN-RATIONALE.md §1](docs/DESIGN-RATIONALE.md).
- Help deploy this against systems you do not own or operate. See *Responsible use*
  in the README.
- Sign an NDA to discuss a bypass. The value of the project depends on bypasses
  being public.
