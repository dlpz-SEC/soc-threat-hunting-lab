#!/bin/bash
# SOC Threat Hunting Lab - Quick Start
# Builds the database, deploys detection views, and prints the triage queue.
#
# Prefers the sqlite3 CLI; falls back to the stdlib Python builder
# (scripts/build_db.py) so it works on machines without the CLI (e.g. a
# default Windows box). Run from anywhere — it cd's to its own directory.

set -e
cd "$(dirname "$0")"

echo "=========================================="
echo "SOC THREAT HUNTING LAB"
echo "=========================================="
echo ""

DB=data/security.db

if command -v sqlite3 &> /dev/null; then
    echo "[1/3] Building database (sqlite3 CLI)..."
    rm -f "$DB"
    sqlite3 "$DB" < data/setup_database.sql
    sqlite3 "$DB" < data/ground_truth.sql
    sqlite3 "$DB" < data/enrichment.sql
    sqlite3 "$DB" < sql/detection_queries.sql
    RUN_SQL() { sqlite3 -header -column "$DB" "$1"; }
else
    echo "[1/3] sqlite3 CLI not found — building via Python (scripts/build_db.py)..."
    python scripts/build_db.py --out "$DB"
    RUN_SQL() { python - "$DB" "$1" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1]); conn.row_factory = sqlite3.Row
rows = conn.execute(sys.argv[2]).fetchall()
if rows:
    cols = rows[0].keys()
    print(" | ".join(cols))
    for r in rows:
        print(" | ".join(str(r[c]) for c in cols))
PY
    }
fi
echo "      Database ready."

echo ""
echo "[2/3] Running detections..."
echo ""

echo "=== HIGH SEVERITY FINDINGS (with ATT&CK + threat intel) ==="
RUN_SQL "
SELECT detection_type, mitre_technique, COALESCE(username, source_ip) AS subject,
       timestamp, COALESCE(intel_tags, '-') AS intel, substr(reason, 1, 60) AS summary
FROM v_triage_queue
WHERE severity = 'HIGH'
ORDER BY timestamp DESC;
"

echo ""
echo "=== PASSWORD SPRAY CAMPAIGNS ==="
RUN_SQL "SELECT source_ip, login_date, accounts_targeted, total_failures, severity FROM v_detect_password_spray;"

echo ""
echo "=== INTEGRITY ISSUES (validate before containment) ==="
RUN_SQL "SELECT device_id, primary_owner, backup_owner, issue FROM v_inventory_mismatch;"
RUN_SQL "SELECT device_id, listed_owner, issue FROM v_orphan_devices;"

echo ""
echo "[3/3] Detection complete."
echo ""
echo "Measured metrics:      docs/METRICS.md     (python scripts/compute_metrics.py)"
echo "Full query output:     results/DETECTION_OUTPUT.md"
echo "Investigation writeup: README.md"
echo ""
echo "Explore interactively (if you have the CLI):"
echo "  sqlite3 -header -column data/security.db 'SELECT * FROM v_triage_queue;'"
