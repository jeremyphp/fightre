# Design rationale

This document explains why FightRE is built the way it is, what each layer can and
cannot conclude, and where the design knowingly trades one property for another.
It is the companion to [THREAT-MODEL.md](THREAT-MODEL.md), which states the
assumptions, and [ARCHITECTURE.md](ARCHITECTURE.md), which states the mechanics.

---

## 1. Scope and non-goals

FightRE is middleware for a web service that ships a browser client and an HTTP
API, and is subject to automated analysis by an adversary who runs the analysis on
their own machine.

**In scope**

- Raising the cost of each *verified* fact an automated pipeline establishes.
- Causing an automated pipeline to record confident but incorrect conclusions.
- Attributing extracted material to the session that extracted it.
- Telling the operator, before shipping, what the build gives away for free.

**Explicitly out of scope**

| Non-goal | Why |
|---|---|
| Preventing reverse engineering | Not achievable on hardware the adversary controls |
| Instruction-level obfuscation | A compiler/virtualiser problem, not a middleware problem |
| Network-layer DDoS or bot filtering | Belongs at the edge; FightRE consumes edge output, does not replace it |
| DRM or licence enforcement | Different threat model (dishonest licensee, not analyst) |
| Client-side tamper *prevention* | Client checks are advisory; see §3 |

Stating the non-goals precisely is not modesty. A security control whose claimed
scope exceeds its actual scope is worse than no control, because it causes the
operator to stop looking.

---

## 2. The asymmetry we are exploiting

An automated reverse-engineering pipeline differs from a human analyst in three
structural ways, and each is exploitable.

### 2.1 It pays per fact, not per session

A human who has understood a protocol reuses that understanding for free. An agent
pays for every observation: a tool invocation, a token budget, a wall-clock
interval. The marginal cost of fact *n+1* never decreases as fast as it does for a
human.

→ Any mechanism that increases cost per observation is effective, even if each
individual increase is small. Proof-of-work, bounded tarpits and per-identity
budgets act here.

### 2.2 It trusts its own observations

An agent's report is assembled from things it observed and recorded, weighted by
confidence. It has no independent ground truth. A human analyst has domain
intuition that says "this key material looks off"; an agent has a schema that says
the response matched.

→ A plausible-but-wrong observation is more damaging than a refusal. Refusal
triggers retry; plausible wrongness is written down as fact.

### 2.3 What it extracts travels

Findings move into reports, datasets, committed test fixtures and follow-up
analyses. The extraction is rarely the final consumer.

→ Marking extracted material makes the *downstream* use of an extraction
attributable, which is a stronger property than preventing the extraction.

These three properties are why the layer model (L0–L5) is organised the way it is:
each layer attacks one of them, and none of them is a tautology about "stopping"
anyone.

---

## 3. Principle: advisory clients, authoritative servers

Every signal that originates on the client is untrusted input. A client can patch
its own environment, forge an attestation payload, or replace the shipped script.

This produces a design rule that constrains the entire client layer:

> A client-side check may increase the *cost* of lying, but it never carries
> enforcement authority. The server derives the verdict from signed evidence and
> from server-observable properties.

Consequences:

- Attestation payloads are HMAC-signed per challenge, so a replayed or altered
  payload is detectable without trusting the client's claim.
- Where a signal cannot be made trustworthy (a self-reported flag), it is weighted
  low enough that it cannot alone cause a block.
- The reference mobile guards (`native/android`, `native/ios`) therefore return
  *evidence*, not verdicts: "this device reports root" is an input, not a decision.

The alternative — trusting client checks — is the most common failure mode in
anti-tamper products, and it fails silently: the product reports "protected" while
the adversary has already patched the check out.

---

## 4. Layer rationale

Each layer answers one bounded question. The value of the decomposition is that a
layer can be evaluated, disabled or replaced without invalidating the others.

### L0 — build audit (offline)

**Question:** what does this artifact give away before any adversary acts?

Everything a static analyser needs is usually shipped by accident: source maps,
unstripped symbols, debug paths, committed secrets, published schemas, internal
hostnames. This is the cheapest possible finding for the adversary and the
cheapest possible fix for the defender, which makes it irrational to skip.

The audit is offline by design: it runs in CI, has no network access, and produces
human-readable or machine-readable output with CI-friendly exit codes.

*Limit:* it reasons about text and headers, not about behaviour. It cannot tell you
whether your protocol is guessable.

### L1 — network budgets

**Question:** is this identity observing at a rate no legitimate client would?

Token buckets per identity, plus path-diversity tracking (an identity that samples
many distinct paths in a short window is behaving like a crawler rather than a
user). Both are statistical, both are trivially defeated by an adversary who slows
down — which is the point: the mechanism converts an unbounded-rate attack into a
time-bounded one.

*Limit:* an adversary willing to spend wall-clock time is unaffected. The cost
model is throughput, not admission.

### L2 — protocol consistency

**Question:** does the wire agree with the client it claims to be?

TLS fingerprints (JA3/JA4), HTTP/2 settings, header order, duplicate headers, and
contradictions between `User-Agent` and `Sec-CH-UA` are properties of the client
stack, not of the client's claims. They are therefore expensive to fake
consistently.

The critical constraint: **these observations are only available at the edge.**
A Python middleware sees a normalised request. So the edge (nginx `ssl_preread`,
HAProxy, Envoy, a CDN worker) computes the fingerprint and HMAC-signs it; the
application verifies the signature. Without that signature the header is a client
claim and is weighted as such.

*Limit:* a sufficiently determined adversary can reproduce a real browser's TLS
stack (uTLS and similar). The mechanism raises cost; it does not create identity.

### L3 — client proof

**Question:** is this really a browser, and is it behaving like one?

A SHA-256 proof-of-work challenge makes each *identity* pay a one-time cost, and
per-identity budgets make that cost recur for identities created in bulk.
Environment attestation (WebDriver artefacts, CDP leaks, patched natives, software
renderers) contributes weak signals that are individually inconclusive.

Sizing is the whole design question. From `launch/bench.py` on the reference
machine, a Python reference solver costs:

| difficulty | median | expected attempts |
|---:|---:|---:|
| 16 | ~24 ms | 2^16 |
| 18 | ~247 ms | 2^18 |
| 20 | ~1.0 s | 2^20 |
| 22 | ~3.0 s | 2^22 |

A legitimate browser solves once and holds an `HttpOnly` attestation cookie. The
asymmetry is therefore *per identity*, not per request: a human pays ~0.3 s once;
an adversary creating N identities pays N × 0.3 s.

*Limit:* difficulty that is tolerable for a desktop is painful for a low-end phone.
Calibrate against the slowest device you support, and treat difficulty as a
per-surface parameter rather than a global constant.

### L4 — application semantics

**Question:** is it using the API the way a client uses it, and is it the client it
says it is?

HMAC request signing with nonce replay defence establishes that the request came
from a session that has the signing key — which is only true for sessions that
passed L3. Honeypot endpoints and fabricated schemas act on the "trusts its own
observations" property from §2.2.

Two notes on the deception design:

- Decoy paths are unreachable by navigation. A legitimate client never encounters
  them; a crawler enumerating a schema does.
- Fabricated material must be *plausible*, not merely wrong. A schema that is
  obviously fake is discarded; a schema that is subtly wrong is recorded. The
  second is the objective.

*Limit:* deception decays. A decoy surface that never changes becomes
recognisable, and an adversary reading the source knows it is decoyed. Treat
rotation as maintenance, not as optional polish.

### L5 — data provenance

**Question:** where did this copy come from?

Canary tokens embedded in fabricated responses, plus zero-width watermarking of
string payloads, make extracted material attributable to a session, a path and a
time. Attribution matters more than prevention here: it converts a leak from an
anonymous event into an identified one, which changes the adversary's calculus.

*Limit:* watermarking survives naive copying and fails against re-typing,
translation or reformatting. Its value is against automated extraction pipelines,
which is precisely the threat model.

---

## 5. Scoring: why noisy-OR and not a model

Signals are combined with a noisy-OR:

```
score = 1 - Π(1 - w_i)
```

over the weights of the signals that fired, scaled to 0–100.

Properties this buys, in order of importance:

1. **Explainability.** Every verdict is a list of (signal, weight). An operator can
   read a block and understand it. A model cannot offer this, and an
   unexplainable block is an unappealable one.
2. **No training data.** There is no corpus of labelled benign/malicious traffic to
   collect, and no drift to maintain.
3. **Bounded interaction.** Signals are independent by construction, so adding a
   signal cannot silently invalidate another; the worst case is a weight that is
   wrong and visibly wrong.
4. **Deterministic replay.** Given the same request snapshot and store state, the
   verdict is reproducible, which makes disputes resolvable.

The cost is real: noisy-OR assumes independence, and correlated signals will
over-count. Where correlation is known (for example, several checks that all read
the same attestation payload), the weights are set so that the correlated group
cannot independently cross a block threshold.

---

## 6. Failure modes we expect

This section exists because a security component without a documented failure
model is a component whose failures will be discovered by users.

| Failure | Symptom | Mitigation |
|---|---|---|
| False positive on privacy browsers | legitimate user challenged repeatedly | observe mode; per-signal allowlist; weight review |
| Corporate TLS inspection | L2 fingerprint looks non-browser for all staff | per-ASN/-proxy calibration; disable L2 for known egress |
| Canary fatigue | operator drowns in attribution alerts | tier canaries by sensitivity; aggregate by session |
| Decoy staleness | adversary recognises the decoy surface | scheduled rotation; versioned decoy sets |
| Store outage | shared state degrades to per-process | local fallback plus failure counter (already implemented) |
| Difficulty miscalibration | mobile users pay seconds, desktops pay nothing | per-surface difficulty; measure on target devices |

The pattern in every mitigation is the same: **make the failure observable before
it becomes an outage.** That is why stores count failures instead of raising, why
observe mode is the default, and why the signal log is a first-class output.

---

## 7. Evaluation methodology

Claims about this class of software are easy to make and hard to check. The project
therefore commits to three rules.

1. **Every performance number comes from a script in the repository.**
   `launch/bench.py` produces the tables in the release notes; the environment is
   printed with the results.
2. **In-process numbers are labelled as such.** A 46 µs decision is not a request
   latency. End-to-end latency also contains the framework, the transport and the
   host's scheduling.
3. **Negative results are published.** If a bypass works, it goes in
   `docs/BYPASS.md` with the reproduction. A defence layer that only publishes
   successes is a marketing artefact.

---

## 8. Related work, and what is different

| Approach | What it does well | Why it is not the same thing |
|---|---|---|
| WAF / CDN bot management | volumetric and reputation-based filtering at the edge | does not fabricate application semantics, cannot attribute extracted data |
| JS obfuscators / virtualisers | raises cost of static reading of client code | says nothing about protocol, budget or provenance |
| RASP / anti-tamper SDKs | detects runtime modification on mobile | mostly client-side authority, which §3 argues against |
| Honeypots / honeytokens (classic) | detects intrusion on the network or host | FightRE applies the same idea inside an HTTP API surface, with attribution |
| Rate limiting | bounds request rate | no notion of *which* requests a legitimate client makes |

The composition is the contribution: cost, consistency, provenance and build
hygiene enforced through one scoring path, with an explicit statement of what each
layer cannot conclude.

---

## 9. Open problems

Stated openly because they are the most interesting part of the design space:

1. **Attacker-adaptive difficulty.** Difficulty is currently static per surface. An
   adversary who probes it can choose when to pay. A schedule that responds to
   observed analysis behaviour would be stronger, and risks punishing legitimate
   users whose behaviour resembles probing.
2. **Decoy generation at build time.** Hand-written decoys are recognisable and
   expensive to maintain. Generating them from the real schema — plausibly wrong,
   consistently wrong — is unsolved in a way that does not leak the real schema.
3. **Attribution across transformations.** Zero-width watermarking survives copying
   but not reformatting. Content-preserving watermarking of structured data is an
   open research area.
4. **Measuring "cost to the adversary".** There is no accepted metric. Wall-clock
   time, token spend and tool-call count are all proxies; none is directly
   comparable across pipelines.

Contributions to any of these are more valuable to the project than additional
detection signals.
