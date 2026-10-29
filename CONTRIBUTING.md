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
