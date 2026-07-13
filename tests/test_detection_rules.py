"""Each detection rule fires on exactly the events ground truth says it should.

These are regression tests: if a rewrite breaks a rule's logic, the expected
event_id set changes and CI goes red. That is what turns SQL worksheets into
version-controlled detection logic.
"""


def test_unfamiliar_country_flags_designed_anchors(flagged, anchors):
    got = flagged("v_detect_unfamiliar_country")
    assert anchors("unfamiliar_country") <= got  # E001 CN (9), E007 DE (50)


def test_unfamiliar_country_flags_terminated_first_success_incidentally(flagged):
    # E016's RU success (102) has no baseline -> caught by the no-baseline
    # branch. This is incidental; Rule 6 owns the terminated case.
    assert 102 in flagged("v_detect_unfamiliar_country")


def test_unfamiliar_country_no_baseline_fires_first_success_only(flagged):
    got = flagged("v_detect_unfamiliar_country")
    assert 135 in got        # E017 first login (the deliberate benign FP)
    assert 136 not in got    # second E017 login must NOT re-fire


def test_impossible_travel_exact_set(flagged):
    assert flagged("v_detect_impossible_travel") == {10, 51}  # E001 return, E007 arrival


def test_impossible_travel_ignores_plausible_us_ca_pair(flagged):
    # E002's US->CA pair (events 20/21) is ~345 km/h — well under the gate.
    got = flagged("v_detect_impossible_travel")
    assert 20 not in got and 21 not in got


def test_impossible_travel_required_velocity_is_quantified(conn):
    rows = {r["event_id"]: r["required_kmh"]
            for r in conn.execute(
                "SELECT event_id, required_kmh FROM v_detect_impossible_travel")}
    assert rows[10] > 900          # E001 CN->US return exceeds the gate
    assert rows[51] > rows[10]     # E007 DE->US is the more extreme case


def test_after_hours_flags_designed_anchor(flagged, anchors):
    assert anchors("after_hours") <= flagged("v_detect_after_hours")  # E011 02:30 (67)


def test_after_hours_catches_attacker_daytime_login_incidentally(flagged):
    # E004's brute-force success at 10:10 is outside E004's learned window.
    assert 43 in flagged("v_detect_after_hours")


def test_after_hours_excludes_service_accounts(conn):
    rows = conn.execute(
        "SELECT COUNT(*) FROM v_detect_after_hours WHERE username LIKE 'svc_%'").fetchone()[0]
    assert rows == 0


def test_brute_force_exact_set(flagged):
    assert flagged("v_detect_brute_force") == {43}  # E004 success after 8 fails


def test_brute_force_counts_uninterrupted_failures(conn):
    fc = conn.execute(
        "SELECT failure_count FROM v_detect_brute_force WHERE event_id = 43").fetchone()[0]
    assert fc == 8


def test_password_spray_is_single_source_many_accounts(conn):
    rows = conn.execute(
        "SELECT source_ip, accounts_targeted FROM v_detect_password_spray").fetchall()
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "45.33.32.201"
    assert rows[0]["accounts_targeted"] == 10


def test_password_spray_excludes_single_account_bruteforce(conn):
    # E012's 25 failures against ONE account must NOT read as a spray.
    ips = {r["source_ip"] for r in conn.execute(
        "SELECT source_ip FROM v_detect_password_spray").fetchall()}
    assert "45.33.32.156" not in ips


def test_failed_bruteforce_is_e012(conn):
    rows = conn.execute(
        "SELECT username, failure_count FROM v_detect_bruteforce_failed").fetchall()
    assert len(rows) == 1
    assert rows[0]["username"] == "E012"
    assert rows[0]["failure_count"] == 25


def test_failed_bruteforce_excludes_spray_members(conn):
    # Spray targets have 2-3 failures each — below the failed-bruteforce
    # threshold — so none should appear here.
    rows = conn.execute(
        "SELECT source_ip FROM v_detect_bruteforce_failed").fetchall()
    assert all(r["source_ip"] != "45.33.32.201" for r in rows)


def test_inactive_account_exact_set(flagged):
    assert flagged("v_detect_inactive_account") == {100, 101, 102}  # all E016


def test_service_accounts_never_flagged(conn):
    views = [
        "v_detect_unfamiliar_country", "v_detect_after_hours",
        "v_detect_brute_force", "v_detect_inactive_account",
    ]
    for view in views:
        n = conn.execute(
            f"SELECT COUNT(*) FROM {view} WHERE username LIKE 'svc_%'").fetchone()[0]
        assert n == 0, f"{view} flagged a service account"
