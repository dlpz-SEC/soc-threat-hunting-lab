#!/bin/bash
# SOC Threat Hunting Lab - Quick Start
# This script sets up the database and runs all detection queries

set -e

echo "=========================================="
echo "SOC THREAT HUNTING LAB"
echo "=========================================="
echo ""

# Check for SQLite
if ! command -v sqlite3 &> /dev/null; then
    echo "ERROR: sqlite3 is required. Install with: apt-get install sqlite3"
    exit 1
fi

# Setup database
echo "[1/4] Setting up database..."
sqlite3 data/security.db < data/setup_database.sql
echo "      ✓ Database created with $(sqlite3 data/security.db 'SELECT COUNT(*) FROM log_in_attempts') login events"

# Create detection views
echo "[2/4] Creating detection views..."
sqlite3 data/security.db < sql/detection_queries.sql
echo "      ✓ Detection rules deployed"

# Run detections
echo "[3/4] Running anomaly detection..."
echo ""

echo "=== HIGH SEVERITY FINDINGS ==="
sqlite3 -header -column data/security.db "
SELECT detection_type, username, user_name, timestamp, substr(reason, 1, 50) as summary
FROM v_triage_queue 
WHERE severity = 'HIGH'
ORDER BY timestamp DESC;
"

echo ""
echo "=== INTEGRITY ISSUES ==="
sqlite3 -header -column data/security.db "
SELECT * FROM v_inventory_mismatch;
SELECT * FROM v_orphan_devices;
"

echo ""
echo "[4/4] Detection complete."
echo ""
echo "Full results available in:"
echo "  - results/EXECUTIVE_SUMMARY.html"
echo "  - results/INVESTIGATION_REPORT.html"
echo "  - results/DETECTION_OUTPUT.md"
echo ""
echo "To explore interactively:"
echo "  sqlite3 -header -column data/security.db"
echo "  > SELECT * FROM v_triage_queue;"
