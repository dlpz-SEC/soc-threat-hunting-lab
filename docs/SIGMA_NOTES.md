# Sigma Coverage Notes

Not every detection in this lab is a Sigma rule, and pretending otherwise
would be dishonest. This note records which detections are expressed as Sigma,
which are not, and why — the reasoning is the point.

## What Sigma models well here

Sigma's strength is a **stateless match over a single event**, optionally
wrapped in a **correlation** that counts or value-counts matches over a window.
Three of the seven detections fit:

| Detection | Rule file | Sigma construct | ATT&CK |
|---|---|---|---|
| Terminated-account auth | `rules/auth/initial_access/terminated_account_authentication.yml` | selection on an enriched `account_status` field | T1078.002 |
| Brute force (failure burst) | `rules/auth/credential_access/bruteforce_failures_then_success.yml` | `event_count` correlation, group-by username | T1110.001 |
| Password spray | `rules/auth/credential_access/password_spray_single_source.yml` | `value_count` of distinct usernames, group-by source_ip | T1110.003 |

### Honest caveats on those three

- **Terminated-account** depends on an `account_status` field that raw auth
  logs do not carry. It only fires after an enrichment join to the identity
  directory (the lab's `employees` table; an IdP/HR feed in production). The
  rule description states this dependency explicitly.
- **Brute force**: base Sigma correlation expresses "≥5 failures in an hour"
  but **not** "…followed by a success with no success in between." That
  temporal ordering is enforced downstream — by `v_detect_brute_force`'s
  `NOT EXISTS` intervening-success check, or a SIEM correlation search. The
  Sigma rule is the failure-burst half; the SQL view is the complete logic.
- **Password spray**: the threshold is **distinct accounts**, not total
  failures. That is the property that distinguishes a spray (breadth) from
  single-account brute force (depth).

## What Sigma does NOT model here — and why

The other four detections are **stateful**: they compare an event against
per-entity history or a geo computation that Sigma's selection/correlation
model cannot express. Forcing them into Sigma would be cargo-culting.

| Detection | Why it is a hunt query, not a Sigma rule |
|---|---|
| Unfamiliar country | Needs a per-user country **baseline** built from a prior window, then a not-in-baseline test. Sigma has no per-entity historical state. |
| Impossible travel | Needs the **previous** login per user (a window/`LAG`) **and** a distance-vs-time velocity computation against a country-distance table. Neither the ordering nor the arithmetic is expressible in Sigma. |
| After-hours | Needs a per-user (or per-department) **learned hour window**, not a fixed cutoff. Same per-entity-state problem as unfamiliar country. |
| Failed brute force | A per-account count is expressible, but it is the exact complement of the spray correlation and is clearer kept as a SQL/SPL analytic beside it. |

These four ship as **SPL** (`queries/splunk/`) and **KQL** (`queries/kql/`)
hunting queries instead. Each carries the same ATT&CK technique and a header
comment explaining the stateful step.

## Validation vs conversion

- **Validation is the CI gate.** `sigma check rules/` runs on every push and
  must exit clean (0 errors). `scripts/validate_rules.py --strict` enforces the
  repo conventions (`[Auth] - ` titles, technique-level `attack.t####` tag,
  mandatory `falsepositives`, `custom:` block).
- **Conversion is best-effort.** Backend support for Sigma **correlation**
  rules is uneven across pySigma backends; a correlation that validates may not
  convert cleanly to every target. We therefore gate CI on validation, not on
  conversion output.
- **Known non-fatal `sigma check` issue.** This pySigma build's ATT&CK tag
  validator recognizes single-word tactic tags (`attack.persistence`) but flags
  the SigmaHQ-standard underscore form of multi-word tactics
  (`attack.credential_access`, `attack.initial_access`) because its internal
  taxonomy stores them hyphenated. The underscore form is the SigmaHQ
  convention (and matches `dlpz-SEC/detection-as-code`), so we keep it; these
  surface as `InvalidATTACKTagIssue` (MEDIUM, non-fatal) and do not fail CI.

## Relationship to the rest of the portfolio

- Rule and CI conventions mirror **[dlpz-SEC/detection-as-code](https://github.com/dlpz-SEC/detection-as-code)**
  (the `custom:` lifecycle block, tag scheme, validation gate).
- The static IP enrichment mirrors **ADTE**'s offline intel table; see
  `data/enrichment.sql` and the README severity-mapping section.
