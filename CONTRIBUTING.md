# Contributing

Thanks for helping. The project is deliberately small: standard library only,
no build step for the Python package, one JavaScript file.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

python -m unittest discover -s tests -v
node --check fightre/client/fightre.js
ruff check .
```

CI runs the same commands on Python 3.9, 3.11 and 3.13.

## Adding a detector

1. Add a `SignalSpec` to `fightre/signals.py` with a layer, a weight and a
   one-line description. Weights are evidence probabilities, not severities:
   ask "if this were the only thing I saw, how sure am I?"
2. Emit the signal from the layer that owns the evidence:
   - headers → `fightre/headers.py`
   - toolchain artefacts → `fightre/agent_detect.py`
   - request semantics → `fightre/signing.py` / `fightre/guard.py`
   - data → `fightre/canary.py`
3. Add a test in `tests/` that asserts both the signal name and the score
   contribution. A detector without a test is a rumour.
4. If the signal is decisive on its own, consider adding it to
   `Policy.DEFAULT_HARD_BLOCK`; if it is bait, add it to
   `Policy.DEFAULT_NEVER_BLOCK`.

## Adding an adapter

Build a `fightre.guard.Request`, call `Guard.evaluate`, then
`Guard.build_response`. `None` means "pass through". See
`fightre/middleware.py` for the ~100-line reference implementation.

## Style

- No new runtime dependencies. If a feature needs one, it goes behind an extra.
- Fail closed on security decisions, fail open on telemetry writes.
- Every public function gets a docstring that says *why*, not just *what*.
- Keep `Guard.evaluate` allocation-light; it runs on every request.

## Commits

Conventional-ish prefixes (`feat:`, `fix:`, `docs:`, `test:`) and one logical
change per commit. Update `CHANGELOG.md` for user-visible changes.

## Sign-off (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. Sign your commits:

```bash
git commit -s -m "feat: detect X"
```

The sign-off line is the whole agreement:

```
Signed-off-by: Your Name <you@example.com>
```

It certifies that you wrote the contribution, or have the right to submit it under
the project license. There is no form to fill in and no email to send, which is why
we chose it: a CLA would stop most drive-by contributors before their first patch.

If you forgot, amend: `git commit --amend -s --no-edit`.

## License of contributions

By submitting a contribution you agree it is licensed under Apache-2.0, the project
license. Do not paste code you cannot license this way; if you are adapting an
existing implementation, say so in the pull request and include its license.

## What gets merged quickly

| Accepted readily | Needs discussion first |
|---|---|
| a new signal with a test asserting its weight contribution | a change to the scoring model |
| an adapter for a framework or gateway | a new runtime dependency |
| documentation fixes, reproducible bug reports | anything that makes a verdict unexplainable |
| a bypass report with a reproduction | weakening an existing detector to reduce false positives |

The last row is deliberate: false positives are usually fixed by tuning weights or
allowlisting, not by removing evidence.