## What changed

<!-- One paragraph. Link the issue if there is one. -->

## Why

<!-- The problem this solves, and why the chosen approach is the smallest one. -->

## Checklist

- [ ] `python -m unittest discover -s tests` passes
- [ ] `node --check fightre/client/fightre.js` passes (if the client changed)
- [ ] No new runtime dependency
- [ ] New or changed signals are documented (spec + weight + test)
- [ ] `CHANGELOG.md` updated for user-visible changes
- [ ] Deception / blocking changes keep the "never block the bait" and
      "challenge before block" rules, or explain why not

## Notes for the reviewer

<!-- Anything that is easy to miss: false positives, rollout implications, config changes. -->
