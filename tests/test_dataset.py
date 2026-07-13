"""Dataset invariants: every event is labeled, config is present, ids explicit.

Guards against silent data drift — a new unlabeled event, a missing config
key, or a re-introduced implicit AUTOINCREMENT id all fail here.
"""


def test_every_event_has_a_ground_truth_label(conn):
    unlabeled = conn.execute(
        "SELECT l.event_id FROM log_in_attempts l "
        "WHERE NOT EXISTS (SELECT 1 FROM ground_truth g WHERE g.event_id = l.event_id)"
    ).fetchall()
    assert unlabeled == []


def test_event_ids_are_explicit_and_contiguous(conn):
    ids = [r[0] for r in conn.execute(
        "SELECT event_id FROM log_in_attempts ORDER BY event_id").fetchall()]
    assert ids == list(range(1, len(ids) + 1))


def test_malicious_and_benign_totals(conn):
    mal = conn.execute(
        "SELECT COUNT(DISTINCT event_id) FROM ground_truth WHERE is_malicious=1").fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM log_in_attempts").fetchone()[0]
    # 1 (E001 CN) + 1 (E001 return) + 9 (bf-e004) + 2 (E007) + 1 (E011)
    # + 25 (bf-e012) + 3 (E016) + 25 (spray) = 67 malicious events.
    assert mal == 67
    assert total == 161


def test_required_hunt_config_keys_present(conn):
    keys = {r[0] for r in conn.execute("SELECT key FROM hunt_config").fetchall()}
    required = {
        "baseline_end", "detection_start", "asof_date", "bf_window_minutes",
        "bf_min_failures", "bf_failed_min_failures", "spray_min_accounts",
        "hour_baseline_min_samples", "hour_tolerance", "max_travel_speed_kmh",
    }
    assert required <= keys


def test_no_duplicate_event_ids(conn):
    dupes = conn.execute(
        "SELECT event_id, COUNT(*) c FROM log_in_attempts GROUP BY event_id HAVING c > 1"
    ).fetchall()
    assert dupes == []
