"""Measure detection quality against ground truth.

The lab plants every anomaly, so ground-truth labels exist
(data/ground_truth.sql). This script computes real precision / recall /
false-positive counts per rule instead of asserting "True Positive Rate:
High", and regenerates the docs that quote those numbers.

Definitions (see data/ground_truth.sql for the label schema):
  * A flagged row is a TRUE POSITIVE if its event/campaign is malicious under
    ANY anomaly_class — incidental catches (after-hours catching an attacker's
    daytime login) count as TPs, not FPs.
  * RECALL is measured against the rule's DESIGNED class only, using anchors
    (is_anchor=1) for event-grain rules and distinct campaign_ids for
    campaign-grain rules.

Outputs:
  * docs/METRICS.md                — full table + methodology
  * results/DETECTION_OUTPUT.md    — real dumps of every view (reproducible)
  * <!-- GEN:* --> marker blocks in README.md and EXECUTIVE_SUMMARY.md

Usage:
  python scripts/compute_metrics.py           # regenerate the docs
  python scripts/compute_metrics.py --check    # exit 1 if any doc is stale (CI)
  python scripts/compute_metrics.py --print     # print metrics to stdout only
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_db import build  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class RuleSpec:
    key: str
    label: str
    view: str
    grain: str            # "event" or "campaign"
    anchor_column: str    # column in the view holding the event_id / campaign_key
    designed_class: str
    mitre: str


# Registry: one entry per detection rule. anchor_column is what the view
# exposes to join back to ground truth.
RULES: list[RuleSpec] = [
    RuleSpec("unfamiliar_country", "Unfamiliar Country", "v_detect_unfamiliar_country",
             "event", "event_id", "unfamiliar_country", "T1078"),
    RuleSpec("impossible_travel", "Impossible Travel", "v_detect_impossible_travel",
             "event", "event_id", "impossible_travel", "T1078"),
    RuleSpec("after_hours", "After-Hours Login", "v_detect_after_hours",
             "event", "event_id", "after_hours", "T1078"),
    RuleSpec("brute_force", "Brute Force (success)", "v_detect_brute_force",
             "event", "event_id", "brute_force_success", "T1110.001"),
    RuleSpec("password_spray", "Password Spray", "v_detect_password_spray",
             "campaign", "campaign_key", "password_spray", "T1110.003"),
    RuleSpec("bruteforce_failed", "Failed Brute Force", "v_detect_bruteforce_failed",
             "campaign", "campaign_key", "brute_force_failed", "T1110.001"),
    RuleSpec("inactive_account", "Inactive Account", "v_detect_inactive_account",
             "event", "event_id", "terminated_account", "T1078.002"),
]


@dataclass
class RuleMetrics:
    spec: RuleSpec
    tp: int
    fp: int
    fn: int
    flagged: int
    fp_events: list[str]
    fn_events: list[str]

    @property
    def precision(self) -> float:
        return self.tp / self.flagged if self.flagged else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp_designed + self.fn
        return self.tp_designed / denom if denom else 1.0

    tp_designed: int = 0


def _event_metrics(conn: sqlite3.Connection, spec: RuleSpec) -> RuleMetrics:
    flagged = [r[0] for r in conn.execute(
        f"SELECT {spec.anchor_column} FROM {spec.view}").fetchall()]
    tp = fp = 0
    fp_events = []
    for eid in flagged:
        malicious = conn.execute(
            "SELECT MAX(is_malicious) FROM ground_truth WHERE event_id = ?",
            (eid,)).fetchone()[0]
        if malicious:
            tp += 1
        else:
            fp += 1
            fp_events.append(str(eid))

    # Recall on the designed class: anchors that should fire.
    anchors = [r[0] for r in conn.execute(
        "SELECT event_id FROM ground_truth WHERE anomaly_class = ? AND is_anchor = 1",
        (spec.designed_class,)).fetchall()]
    flagged_set = set(flagged)
    tp_designed = sum(1 for a in anchors if a in flagged_set)
    fn_events = [str(a) for a in anchors if a not in flagged_set]

    m = RuleMetrics(spec, tp, fp, len(fn_events), len(flagged), fp_events, fn_events)
    m.tp_designed = tp_designed
    return m


def _campaign_metrics(conn: sqlite3.Connection, spec: RuleSpec) -> RuleMetrics:
    # Expected campaigns of the designed class.
    expected = [r[0] for r in conn.execute(
        "SELECT DISTINCT campaign_id FROM ground_truth "
        "WHERE anomaly_class = ? AND campaign_id IS NOT NULL",
        (spec.designed_class,)).fetchall()]

    # Map each flagged campaign_key back to the malicious event members it
    # covers, and to a campaign_id via those members.
    flagged_keys = [r[0] for r in conn.execute(
        f"SELECT {spec.anchor_column} FROM {spec.view}").fetchall()]

    covered_campaigns: set[str] = set()
    tp = fp = 0
    fp_events = []
    for key in flagged_keys:
        # A campaign_key is source_ip|date (spray) or user|ip|date (failed bf).
        # Resolve its member events by matching the login rows, then look up
        # whether those events are malicious and which campaign they belong to.
        parts = key.split("|")
        if len(parts) == 2:
            ip, date = parts
            member_sql = ("SELECT event_id FROM log_in_attempts "
                          "WHERE source_ip = ? AND login_date = ? AND success = 0")
            member_args = (ip, date)
        else:
            user, ip, date = parts
            member_sql = ("SELECT event_id FROM log_in_attempts "
                          "WHERE username = ? AND source_ip = ? AND login_date = ? "
                          "AND success = 0")
            member_args = (user, ip, date)
        members = [r[0] for r in conn.execute(member_sql, member_args).fetchall()]
        classes = conn.execute(
            "SELECT DISTINCT campaign_id FROM ground_truth "
            "WHERE event_id IN ({}) AND campaign_id IS NOT NULL".format(
                ",".join("?" * len(members))), members).fetchall() if members else []
        campaign_ids = {r[0] for r in classes}
        malicious = conn.execute(
            "SELECT MAX(is_malicious) FROM ground_truth WHERE event_id IN ({})".format(
                ",".join("?" * len(members))), members).fetchone()[0] if members else 0
        if malicious:
            tp += 1
            covered_campaigns |= campaign_ids
        else:
            fp += 1
            fp_events.append(key)

    fn_campaigns = [c for c in expected if c not in covered_campaigns]
    m = RuleMetrics(spec, tp, fp, len(fn_campaigns), len(flagged_keys), fp_events, fn_campaigns)
    m.tp_designed = len([c for c in expected if c in covered_campaigns])
    return m


def compute(conn: sqlite3.Connection) -> list[RuleMetrics]:
    out = []
    for spec in RULES:
        if spec.grain == "event":
            out.append(_event_metrics(conn, spec))
        else:
            out.append(_campaign_metrics(conn, spec))
    return out


def dataset_summary(conn: sqlite3.Connection) -> dict:
    q = lambda sql: conn.execute(sql).fetchone()[0]
    integrity = (q("SELECT COUNT(*) FROM v_orphan_devices")
                 + q("SELECT COUNT(*) FROM v_inventory_mismatch")
                 + q("SELECT COUNT(*) FROM v_users_without_devices"))
    return {
        "events": q("SELECT COUNT(*) FROM log_in_attempts"),
        "malicious_events": q("SELECT COUNT(DISTINCT event_id) FROM ground_truth WHERE is_malicious = 1"),
        "employees": q("SELECT COUNT(*) FROM employees"),
        "devices": q("SELECT COUNT(*) FROM machines"),
        "triage_rows": q("SELECT COUNT(*) FROM v_triage_queue"),
        "high": q("SELECT COUNT(*) FROM v_triage_queue WHERE severity = 'HIGH'"),
        "medium": q("SELECT COUNT(*) FROM v_triage_queue WHERE severity = 'MEDIUM'"),
        "low": q("SELECT COUNT(*) FROM v_triage_queue WHERE severity = 'LOW'"),
        "integrity_issues": integrity,
        "critical_patch": q("SELECT COUNT(*) FROM v_patch_status WHERE patch_risk = 'CRITICAL'"),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_metrics_table(metrics: list[RuleMetrics]) -> str:
    lines = [
        "| Detection Rule | ATT&CK | Grain | Flagged | TP | FP | FN | Precision | Recall |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for m in metrics:
        lines.append(
            f"| {m.spec.label} | {m.spec.mitre} | {m.spec.grain} | {m.flagged} | "
            f"{m.tp} | {m.fp} | {m.fn} | {m.precision:.2f} | {m.recall:.2f} |")
    # Aggregate (micro-averaged over event/campaign decisions).
    tp = sum(m.tp for m in metrics)
    fp = sum(m.fp for m in metrics)
    flagged = sum(m.flagged for m in metrics)
    tp_des = sum(m.tp_designed for m in metrics)
    fn = sum(m.fn for m in metrics)
    micro_p = tp / flagged if flagged else 1.0
    micro_r = tp_des / (tp_des + fn) if (tp_des + fn) else 1.0
    lines.append(
        f"| **Overall (micro)** | — | — | **{flagged}** | **{tp}** | **{fp}** | "
        f"**{fn}** | **{micro_p:.2f}** | **{micro_r:.2f}** |")
    return "\n".join(lines)


def render_metrics_doc(metrics: list[RuleMetrics], summary: dict) -> str:
    fp_notes = []
    for m in metrics:
        if m.fp_events:
            fp_notes.append(f"- **{m.spec.label}** — {m.fp} FP: `{', '.join(m.fp_events)}`")
    fp_block = "\n".join(fp_notes) if fp_notes else "- None."
    benign = summary['events'] - summary['malicious_events']
    uc_precision = next(m.precision for m in metrics if m.spec.key == 'unfamiliar_country')
    return f"""# Detection Metrics

<!-- Generated by scripts/compute_metrics.py — do not edit by hand. -->

Measured against ground-truth labels (`data/ground_truth.sql`) over \
{summary['events']} login events ({summary['malicious_events']} malicious, {benign} benign).

## Per-rule performance

{render_metrics_table(metrics)}

## False positives (by design and otherwise)

{fp_block}

## Method

- **True positive** — a flagged row whose event or campaign is malicious under
  *any* labeled anomaly class. Incidental catches count: when the after-hours
  rule flags an attacker's daytime login (E004's 10:10 brute-force success
  falls outside that user's learned window), that is a real detection, not a
  false positive.
- **Recall** — measured against each rule's *designed* class only. Rule 1
  (Unfamiliar Country) incidentally catches the terminated account E016, but
  Rule 6 owns that case, so it neither helps nor hurts Rule 1's recall.
- **Grain** — event-grain rules are scored per `event_id`; campaign-grain
  rules (spray, failed brute force) are scored per distinct campaign.

## The one deliberate false positive

The dataset seeds a dormant account (E017) whose first activity lands in the
detection window. It has no geographic baseline, so Rule 1's no-baseline
branch flags its first login as MEDIUM. This is the honest cost of catching
first-time-from-a-new-country logins, and it is why Rule 1's precision is \
{uc_precision:.2f}, not 1.00. Distinguishing this benign new/dormant account from the terminated
account E016 is exactly the new-hire-vs-terminated call the no-baseline branch
is built to make.

## Caveat

This is a synthetic, low-noise dataset built to exercise detection logic.
Real telemetry carries far more benign anomalies (legitimate travel, VPN
egress, shift workers, automation), so production precision will be lower than
these figures. The value here is the *method* — labeled ground truth plus a
reproducible harness — not the absolute numbers.
"""


def render_detection_output(conn: sqlite3.Connection) -> str:
    def dump(title: str, sql: str) -> str:
        rows = conn.execute(sql).fetchall()
        if not rows:
            return f"### {title}\n\n_(no rows)_\n"
        cols = rows[0].keys()
        head = "| " + " | ".join(cols) + " |"
        sep = "| " + " | ".join("---" for _ in cols) + " |"
        body = "\n".join("| " + " | ".join(str(r[c]) for c in cols) + " |" for r in rows)
        return f"### {title}\n\n{head}\n{sep}\n{body}\n"

    sections = [
        ("Triage queue (v_triage_queue)",
         "SELECT detection_type, mitre_technique, severity, COALESCE(username, source_ip) AS subject, "
         "timestamp, COALESCE(intel_tags,'-') AS intel FROM v_triage_queue"),
        ("Unfamiliar country (v_detect_unfamiliar_country)",
         "SELECT event_id, username, anomaly_country, baseline_state, severity FROM v_detect_unfamiliar_country ORDER BY event_id"),
        ("Impossible travel (v_detect_impossible_travel)",
         "SELECT event_id, username, country_1, country_2, hours_apart, required_kmh, severity FROM v_detect_impossible_travel ORDER BY event_id"),
        ("After-hours (v_detect_after_hours)",
         "SELECT event_id, username, login_hour, baseline_source, window_start, window_end FROM v_detect_after_hours ORDER BY event_id"),
        ("Brute force (v_detect_brute_force)",
         "SELECT event_id, username, failure_count, success_ip FROM v_detect_brute_force ORDER BY event_id"),
        ("Password spray (v_detect_password_spray)",
         "SELECT source_ip, login_date, accounts_targeted, total_failures, severity FROM v_detect_password_spray"),
        ("Failed brute force (v_detect_bruteforce_failed)",
         "SELECT username, source_ip, failure_count FROM v_detect_bruteforce_failed"),
        ("Inactive account (v_detect_inactive_account)",
         "SELECT event_id, username, outcome, country FROM v_detect_inactive_account ORDER BY event_id"),
        ("Orphan devices (v_orphan_devices)",
         "SELECT device_id, listed_owner, issue FROM v_orphan_devices"),
        ("Inventory mismatch (v_inventory_mismatch)",
         "SELECT device_id, primary_owner, backup_owner FROM v_inventory_mismatch"),
        ("Users without devices (v_users_without_devices)",
         "SELECT employee_id, employee_name, department FROM v_users_without_devices ORDER BY employee_id"),
        ("Critical patch posture (v_patch_status)",
         "SELECT device_id, owner_name, days_since_patch, patch_risk FROM v_patch_status WHERE patch_risk='CRITICAL' ORDER BY days_since_patch DESC"),
    ]
    body = "\n".join(dump(t, s) for t, s in sections)
    return ("# Detection Output\n\n"
            "<!-- Generated by scripts/compute_metrics.py — do not edit by hand. -->\n\n"
            "Reproduce any table with, e.g., "
            "`sqlite3 -header -column data/security.db 'SELECT * FROM v_triage_queue;'`\n\n"
            + body)


def render_headline(summary: dict, metrics: list[RuleMetrics]) -> str:
    tp = sum(m.tp for m in metrics)
    fp = sum(m.fp for m in metrics)
    flagged = sum(m.flagged for m in metrics)
    micro_p = tp / flagged if flagged else 1.0
    return (
        f"- **{summary['events']} login events** across {summary['employees']} accounts "
        f"and {summary['devices']} devices\n"
        f"- **{summary['triage_rows']} triage findings** "
        f"({summary['high']} HIGH / {summary['medium']} MEDIUM / {summary['low']} LOW)\n"
        f"- **{summary['integrity_issues']} data-integrity issues** "
        f"(orphan devices + inventory mismatches + users-without-devices)\n"
        f"- **{summary['critical_patch']} critically outdated endpoints** "
        f"(>180 days since patch)\n"
        f"- **Measured detection precision {micro_p:.2f}** across all rules "
        f"(see [docs/METRICS.md](docs/METRICS.md))")


# ---------------------------------------------------------------------------
# Marker-block writing
# ---------------------------------------------------------------------------

def replace_block(text: str, name: str, content: str) -> str:
    start = f"<!-- GEN:{name} -->"
    end = f"<!-- /GEN:{name} -->"
    block = f"{start}\n{content}\n{end}"
    if start in text and end in text:
        pre = text[: text.index(start)]
        post = text[text.index(end) + len(end):]
        return pre + block + post
    return text  # marker absent — leave untouched


def _targets(conn, metrics, summary):
    """Return {path: new_content} for every generated / marker-bearing file."""
    out = {
        REPO_ROOT / "docs" / "METRICS.md": render_metrics_doc(metrics, summary),
        REPO_ROOT / "results" / "DETECTION_OUTPUT.md": render_detection_output(conn),
    }
    for rel in ("README.md", "EXECUTIVE_SUMMARY.md"):
        path = REPO_ROOT / rel
        if path.exists():
            text = path.read_text(encoding="utf-8")
            text = replace_block(text, "headline", render_headline(summary, metrics))
            text = replace_block(text, "metrics", render_metrics_table(metrics))
            out[path] = text
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute detection metrics and regenerate docs.")
    parser.add_argument("--check", action="store_true", help="Exit 1 if any generated doc is stale.")
    parser.add_argument("--print", dest="print_only", action="store_true", help="Print metrics only.")
    args = parser.parse_args()

    conn = build()
    metrics = compute(conn)
    summary = dataset_summary(conn)

    if args.print_only:
        print(render_metrics_table(metrics))
        print()
        print(render_headline(summary, metrics))
        return 0

    targets = _targets(conn, metrics, summary)

    if args.check:
        stale = []
        for path, content in targets.items():
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current != content:
                stale.append(path.relative_to(REPO_ROOT).as_posix())
        if stale:
            print("STALE (run scripts/compute_metrics.py):")
            for s in stale:
                print(f"  - {s}")
            return 1
        print("All generated docs are up to date.")
        return 0

    for path, content in targets.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="\n" forces LF on every platform so the --check gate is
        # byte-stable (no Windows CRLF churn vs the LF-normalized repo).
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(REPO_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
