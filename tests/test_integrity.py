"""Phase 4 asset-integrity views catch the seeded inventory problems.

The DEV-011 case is the senior point: the backup names E007 as owner, and
E007 is the impossible-travel subject — so containment driven off the wrong
inventory would isolate the wrong person's device.
"""


def test_orphan_device(conn):
    rows = conn.execute("SELECT device_id, listed_owner FROM v_orphan_devices").fetchall()
    assert len(rows) == 1
    assert rows[0]["device_id"] == "DEV-099"
    assert rows[0]["listed_owner"] == "E999"


def test_inventory_mismatch_names_both_owners(conn):
    rows = conn.execute(
        "SELECT device_id, primary_owner, backup_owner FROM v_inventory_mismatch").fetchall()
    assert len(rows) == 1
    r = rows[0]
    assert r["device_id"] == "DEV-011"
    assert r["primary_owner"] == "E011"
    assert r["backup_owner"] == "E007"


def test_mismatch_backup_owner_is_the_travel_subject(conn):
    # The wrong-device-containment scenario only bites if E007 is a live
    # investigation subject — assert that link holds.
    backup_owner = conn.execute(
        "SELECT backup_owner FROM v_inventory_mismatch WHERE device_id='DEV-011'").fetchone()[0]
    travel_subjects = {r[0] for r in conn.execute(
        "SELECT username FROM v_detect_impossible_travel").fetchall()}
    assert backup_owner in travel_subjects


def test_users_without_devices(conn):
    ids = {r[0] for r in conn.execute(
        "SELECT employee_id FROM v_users_without_devices").fetchall()}
    assert ids == {"E017", "E018", "E019", "E020"}


def test_terminated_user_not_reported_as_missing_device(conn):
    # E016 is terminated, not an active user without a device.
    ids = {r[0] for r in conn.execute(
        "SELECT employee_id FROM v_users_without_devices").fetchall()}
    assert "E016" not in ids


def test_srv001_critical_patch_age(conn):
    row = conn.execute(
        "SELECT days_since_patch, patch_risk FROM v_patch_status WHERE device_id='SRV-001'").fetchone()
    assert row["days_since_patch"] == 285
    assert row["patch_risk"] == "CRITICAL"
