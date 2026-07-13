"""Static threat-intel enrichment reaches the triage queue.

Replaces the old "suspicious because it isn't 10.x" reasoning: the source is
named against a static feed that mirrors ADTE's offline intel table.
"""


def test_tor_exit_named_on_brute_force(conn):
    row = conn.execute(
        "SELECT intel_source, intel_tags FROM v_triage_queue "
        "WHERE detection_type='BRUTE_FORCE'").fetchone()
    assert row["intel_source"] == "mock-tor-list"
    assert "tor-exit" in row["intel_tags"]


def test_scanner_named_on_spray(conn):
    row = conn.execute(
        "SELECT intel_tags FROM v_triage_queue WHERE detection_type='PASSWORD_SPRAY'").fetchone()
    assert "scanner" in row["intel_tags"]


def test_scanner_named_on_failed_bruteforce(conn):
    row = conn.execute(
        "SELECT intel_tags FROM v_triage_queue WHERE detection_type='BRUTEFORCE_FAILED'").fetchone()
    assert "scanner" in row["intel_tags"]


def test_ru_source_is_an_unenriched_feed_gap(conn):
    # E016's RU success comes from 95.213.45.67, absent from every feed.
    # The row must still surface — just without intel tags.
    rows = conn.execute(
        "SELECT intel_tags FROM v_triage_queue "
        "WHERE source_ip='95.213.45.67'").fetchall()
    assert rows
    assert all(r["intel_tags"] is None for r in rows)


def test_enrichment_matches_adte_mock_ranges(conn):
    # The lab's static table must agree with the ADTE ranges it mirrors.
    tor = conn.execute(
        "SELECT confidence, source FROM ip_enrichment WHERE cidr='185.220.101.0/24'").fetchone()
    assert tor["confidence"] == 0.85
    assert tor["source"] == "mock-tor-list"
    scanner = conn.execute(
        "SELECT confidence FROM ip_enrichment WHERE cidr='45.33.32.0/24'").fetchone()
    assert scanner["confidence"] == 0.75
