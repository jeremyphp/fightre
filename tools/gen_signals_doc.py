"""Generate docs/SIGNALS.md from the signal catalogue.

Usage: python tools/gen_signals_doc.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fightre.signals import LIBRARY  # noqa: E402

HEADER = """# Signal catalogue

Generated from `fightre/signals.py` - do not edit by hand. Regenerate with:

```bash
python tools/gen_signals_doc.py
```

Weights are evidence probabilities in `0..100`; the scoring engine combines them
with a noisy-OR. A `hard-block` marker means the signal is decisive on its own
and bypasses the score bands.
"""


def main() -> int:
    lines = [HEADER, "| signal | layer | weight | hard-block | description |",
             "| --- | --- | --- | --- | --- |"]
    for name in sorted(LIBRARY, key=lambda n: (str(LIBRARY[n].layer.value), n)):
        spec = LIBRARY[name]
        hard = "yes" if spec.critical else ""
        lines.append(
            f"| `{name}` | {spec.layer.value} | {spec.weight:g} | {hard} | {spec.description} |"
        )
    lines.append("")
    lines.append(f"_{len(LIBRARY)} signals across 5 layers._")
    target = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "SIGNALS.md"
    )
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {target} ({len(LIBRARY)} signals)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
