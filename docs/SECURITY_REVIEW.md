# Detection Review — False-Positive Validation

**Date:** 2026-07-13
**Method:** Trail of Bits `fp-check` three-phase methodology, applied manually,
plus empirical false-positive measurement against ground-truth labels.

## Tooling honesty

The Trail of Bits `fp-check` plugin was **not installed in this environment**
(only the `claude-plugins-official` marketplace is present; `trailofbits/skills`
is not). I therefore did not run the plugin. Instead I:

1. applied `fp-check`'s published **three-phase gate** — *does the signal reach
   the detection → is the flagged behavior attacker-meaningful → does it
   matter* — by hand to each rule's flagged set, and
2. **measured** the false-positive rate directly, which the planted ground truth
   (`data/ground_truth.sql`) makes possible and which is a stronger check than a
   qualitative gate: see `docs/METRICS.md`.

If the plugin is later installed, re-run it against `rules/` and this file
should be updated with its output.

## Candidate-by-candidate result

`fp-check`'s job on a detection is to separate true detections from
false-positive / operational-robustness artifacts. Reviewing each rule's
flagged events against ground truth:

| Rule | Flagged | Verdict |
|---|---|---|
| Unfamiliar country | 4 | 3 true (E001/E007/E016), **1 robustness artifact** — E017 dormant account, no baseline. Retained and documented, not suppressed. |
| Impossible travel | 2 | Both true. Review also confirmed the *previous* `country != country` logic carried a latent FP (E002's legitimate US↔CA travel); the velocity gate removes it. |
| After-hours | 5 | All true (incidental catches of already-malicious events). Flagged as a **weak signal** prone to FPs in real multi-timezone orgs — noted in the rule's tuning notes. |
| Brute force (success) | 1 | True. Review surfaced a **correctness defect** in the previous logic (a single failure counted toward multiple successes); fixed with a `NOT EXISTS` intervening-success check. |
| Password spray | 1 | True. Previous per-account grouping could not detect a real spray at all — a **coverage gap**, now closed by per-source grouping. |
| Failed brute force | 1 | True (E012, correctly reclassified from "spray" to failed single-account brute force — the original label was wrong). |
| Inactive account | 3 | All true, precision 1.00. |

## Headline finding

One candidate detection — the unfamiliar-country flag on the dormant account
E017 — is an **operational-robustness artifact, not a true positive**: it fires
only because the account has no geographic baseline. This is exactly the class
of finding `fp-check` exists to surface. Per the methodology it is **not**
silently dropped; it is retained as the documented, measured cost of catching
first-login-from-a-new-country activity, and is why Rule 1's precision is 0.75
rather than a suspicious 1.00 (`docs/METRICS.md`).

The review additionally surfaced three issues in the *pre-overhaul* detections —
a brute-force counting defect, an impossible-travel FP, and a spray coverage
gap — all fixed in this revision.
