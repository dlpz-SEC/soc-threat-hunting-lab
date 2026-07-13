"""Score the lab's triage findings through ADTE — the manual→automated handoff.

This lab flags; ADTE (the Autonomous Detection Triage Engine) scores and
routes. The bridge builds one NormalizedIncident per flagged user from the
lab's detection-window events, runs ADTE's deterministic 0-100 engine fully
OFFLINE, and writes the comparison artifacts:

  results/adte_handoff.json   — machine-readable scores per user
  docs/ADTE_HANDOFF.md        — lab severity vs ADTE verdict, per-signal
                                rationale, and the divergences worth reading

Offline guarantees (deliberate, load-bearing):
  * Imports ONLY adte.engine / adte.models / adte.intel.sigma_fp_registry /
    adte.store.user_history. NEVER adte.cli or adte.server — adte/cli.py runs
    load_dotenv() at import time against ADTE's real .env; with live API keys
    that flips the intel aggregator into network mode.
  * Pops ADTE_ABUSEIPDB_KEY / ADTE_VT_API_KEY / ADTE_OTX_KEY before scoring,
    mirroring ADTE's own test conftest. With no keys, enrichment resolves
    against ADTE's static offline table (185.220.101.0/24 tor-exit,
    45.33.32.0/24 scanner — the same ranges data/enrichment.sql mirrors).

Usage:
  python scripts/adte_bridge.py          # requires: pip install -e <adte repo>
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from build_db import build  # noqa: E402

# --- Offline pin BEFORE any ADTE machinery can read the environment ---------
for _key in ("ADTE_ABUSEIPDB_KEY", "ADTE_VT_API_KEY", "ADTE_OTX_KEY"):
    os.environ.pop(_key, None)

try:
    from adte.engine import TriageEngine  # noqa: E402
    from adte.intel.sigma_fp_registry import FPRegistry  # noqa: E402
    from adte.models import GeoLocation, NormalizedIncident, SignInMetadata  # noqa: E402
    from adte.store.user_history import get_user_profile  # noqa: E402
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "ADTE is not importable. Install it into this venv first:\n"
        "  pip install -e C:\\Users\\david\\Projects\\adte-detection-triage-engine\n"
        f"(original error: {exc})"
    ) from exc

# Country centroids (same coordinates that produced data/enrichment.sql's
# country_distance table). ADTE's impossible-travel signal reads lat/lon, not
# country codes; its own velocity gate is 800 km/h.
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "US": (39.8, -98.6),
    "CA": (56.1, -106.3),
    "CN": (35.9, 104.2),
    "DE": (51.2, 10.4),
    "RU": (61.5, 105.3),
}

UPN_SUFFIX = "@lab.local"


def _sign_in(row) -> SignInMetadata:
    lat, lon = COUNTRY_CENTROIDS[row["country"]]
    ts = datetime.fromisoformat(f"{row['login_date']} {row['login_time']}").replace(
        tzinfo=timezone.utc
    )
    return SignInMetadata(
        user_principal_name=f"{row['username'].lower()}{UPN_SUFFIX}",
        ip_address=row["source_ip"],
        type="authentication",
        location=GeoLocation(lat=lat, lon=lon, country=row["country"]),
        auth_status="success" if row["success"] else "failure",
        timestamp=ts,
    )


def collect_findings(conn) -> dict[str, dict]:
    """Flagged users + their lab-side context from the triage queue."""
    rows = conn.execute(
        "SELECT username, detection_type, severity, mitre_technique "
        "FROM v_triage_queue WHERE username IS NOT NULL"
    ).fetchall()
    users: dict[str, dict] = {}
    sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for r in rows:
        u = users.setdefault(
            r["username"],
            {"detections": [], "techniques": set(), "lab_severity": "LOW"},
        )
        if r["detection_type"] not in u["detections"]:
            u["detections"].append(r["detection_type"])
        u["techniques"].add(r["mitre_technique"])
        if sev_rank[r["severity"]] > sev_rank[u["lab_severity"]]:
            u["lab_severity"] = r["severity"]
    return users


def score_user(conn, username: str, techniques: set[str]) -> dict:
    """One NormalizedIncident per user over their detection-window events."""
    events = conn.execute(
        "SELECT username, login_date, login_time, country, success, source_ip "
        "FROM v_login_events WHERE username = ? "
        "AND login_date >= (SELECT value FROM hunt_config WHERE key='detection_start') "
        "ORDER BY ts",
        (username,),
    ).fetchall()
    sign_ins = [_sign_in(r) for r in events]
    for si in sign_ins:  # advisory metadata only — never read by scoring
        si.technique_ids = sorted(techniques)

    incident = NormalizedIncident(
        incident_id=f"SOC-LAB-{username}",
        user=f"{username.lower()}{UPN_SUFFIX}",
        source="generic",
        events=sign_ins,
        created_time=sign_ins[-1].timestamp if sign_ins else datetime.now(timezone.utc),
    )
    profile = get_user_profile(incident.user)  # sparse for unknown users
    engine = TriageEngine(incident, profile, FPRegistry.load())
    return engine.enrich().score().decide().to_output()


def run() -> dict:
    conn = build()
    findings = collect_findings(conn)
    results = {}
    for username in sorted(findings):
        out = score_user(conn, username, findings[username]["techniques"])
        results[username] = {
            "lab": {
                "severity": findings[username]["lab_severity"],
                "detections": findings[username]["detections"],
                "techniques": sorted(findings[username]["techniques"]),
            },
            "adte": {
                "risk_score": out["risk_score"],
                "verdict": out["verdict"],
                "display_severity": out["report"]["severity"],
                "confidence": out["confidence"],
                "recommended_action": out["recommended_action"],
                "actions": out["actions"],
                "rationale": out["rationale"],
            },
        }
    conn.close()
    return results


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(results: dict) -> str:
    def sig_summary(rationale: list[dict]) -> str:
        firing = [r for r in rationale if r["score"] > 0]
        firing.sort(key=lambda r: -r["score"])
        return "; ".join(f"{r['signal']} {r['score']:g}" for r in firing) or "—"

    rows = "\n".join(
        f"| {u} | {d['lab']['severity']} | {', '.join(d['lab']['detections'])} | "
        f"**{d['adte']['risk_score']}** | {d['adte']['verdict']} | "
        f"{sig_summary(d['adte']['rationale'])} |"
        for u, d in results.items()
    )

    return f"""# ADTE Handoff — Manual Triage, Automatically Scored

<!-- Generated by scripts/adte_bridge.py — do not edit by hand. -->

This lab is the **manual precursor** to [ADTE](https://github.com/dlpz-SEC/adte-detection-triage-engine):
an analyst-style workflow with flat HIGH/MEDIUM/LOW severities. This document
is the handoff made concrete — every user the lab flagged, re-scored by ADTE's
deterministic 0–100 engine, **fully offline** (no API keys; enrichment resolves
against ADTE's static intel table, the same ranges `data/enrichment.sql`
mirrors).

## Scores

| User | Lab severity | Lab detections | ADTE score | ADTE verdict | Firing signals |
|---|---|---|---|---|---|
{rows}

Verdict bands: `low_risk` < 30 ≤ `medium_risk` ≤ 70 < `high_risk`.

## What the engine sees that the lab's flat severities cannot

- **Signal stacking.** The lab emits one label per rule. ADTE sums weighted
  signals: a user hit by brute-force failures *and* a bad-reputation source
  *and* an odd hour scores higher than any single rule could express.
- **The E012 inversion.** The lab ranks E012's failed brute force MEDIUM
  (attack didn't land). ADTE ranks it the **top score in the table** — the
  failure burst reads as MFA-fatigue-shaped (25), the source is a known
  scanner (20), and the 04:00 timing is anomalous (9.3). Both views are
  defensible: the lab prioritizes *impact* (no compromise), the engine
  prioritizes *signal density* (an active, attributable attacker). Exactly the
  kind of disagreement a scoring engine exists to force into the open.
- **The feed gap is visible in the numbers.** E016's RU source
  (95.213.45.67) is absent from the offline intel table, so its
  `ip_reputation` contributes 0 — the score leans on travel velocity and the
  odd hour instead. In production, live AbuseIPDB/VT/OTX lookups would close
  that gap; the lab documents it rather than pretending otherwise.
- **The benign case stays benign.** E017 (the lab's one deliberate false
  positive — dormant account, no baseline) scores at the bottom of the table.
  The engine agrees with the ground truth: this is the manual-vs-automated
  consistency check working.

## Known, deliberate divergences (bridge limitations, documented)

- **Unmanaged-device constant.** The lab schema has no device IDs, so ADTE's
  `device_novelty` signal contributes a flat 7.5/15 ("unmanaged devices") to
  every user. It is a property of the dataset, not a differentiator.
- **Hour baselines differ by design.** The lab learns per-user hour windows
  from baseline data; ADTE applies its default 07:00–19:00 UTC window for
  unknown users. Where the two disagree (e.g. a 05:00 login inside a user's
  learned window), that is the manual-vs-engine divergence this handoff
  exists to surface.
- **Geo is country-centroid.** Same limitation as the lab's impossible-travel
  rule; ADTE's own 800 km/h gate applies (the lab's is 900).

## Reproduce

```bash
pip install -e <path-to-adte-repo>
python scripts/adte_bridge.py
```

Machine-readable output: `results/adte_handoff.json`.
"""


def main() -> int:
    results = run()
    (REPO_ROOT / "results" / "adte_handoff.json").write_text(
        json.dumps(results, indent=2, default=str) + "\n",
        encoding="utf-8", newline="\n",
    )
    (REPO_ROOT / "docs" / "ADTE_HANDOFF.md").write_text(
        render_markdown(results), encoding="utf-8", newline="\n"
    )
    print(f"{'User':<6} {'Lab':<8} {'ADTE':>4}  Verdict")
    for u, d in results.items():
        print(f"{u:<6} {d['lab']['severity']:<8} {d['adte']['risk_score']:>4}  {d['adte']['verdict']}")
    print("\nwrote results/adte_handoff.json, docs/ADTE_HANDOFF.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
