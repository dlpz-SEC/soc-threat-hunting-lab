"""Build the lab database from the SQL seed and view files.

Uses the Python stdlib sqlite3 module only — no sqlite3 CLI required, so it
runs identically on Windows dev boxes and Linux CI.

Usage:
    python scripts/build_db.py                 # writes data/security.db
    python scripts/build_db.py --out other.db  # custom path

From code (tests, metrics):
    from build_db import build
    conn = build()                             # in-memory database
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Order matters: ground_truth.sql reads log_in_attempts (setup), and the
# detection views read hunt_config + the enrichment tables. Load accordingly.
SQL_FILES = (
    REPO_ROOT / "data" / "setup_database.sql",
    REPO_ROOT / "data" / "ground_truth.sql",
    REPO_ROOT / "data" / "enrichment.sql",
    REPO_ROOT / "sql" / "detection_queries.sql",
)


def build(target: str = ":memory:") -> sqlite3.Connection:
    """Create a connection and execute every SQL file in dependency order."""
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    # Foreign keys are intentionally NOT enforced: DEV-099 -> E999 is a
    # deliberate orphan the integrity views are designed to catch.
    for path in SQL_FILES:
        conn.executescript(path.read_text(encoding="utf-8"))
    conn.commit()
    return conn


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the SOC lab SQLite database.")
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "data" / "security.db"),
        help="Output database path (default: data/security.db).",
    )
    args = parser.parse_args()

    out_path = Path(args.out)
    if out_path.exists():
        out_path.unlink()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    conn = build(str(out_path))
    n_events = conn.execute("SELECT COUNT(*) FROM log_in_attempts").fetchone()[0]
    n_flagged = conn.execute("SELECT COUNT(*) FROM v_triage_queue").fetchone()[0]
    conn.close()
    print(f"Built {out_path} — {n_events} login events, {n_flagged} triage rows.")


if __name__ == "__main__":
    main()
