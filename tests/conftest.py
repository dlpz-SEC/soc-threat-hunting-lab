"""Shared fixtures: an in-memory lab database built from the SQL files.

Stdlib sqlite3 only — no CLI dependency, so the suite runs identically on a
Windows dev box and Linux CI.
"""

import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from build_db import build  # noqa: E402


@pytest.fixture(scope="session")
def conn() -> sqlite3.Connection:
    connection = build()
    yield connection
    connection.close()


@pytest.fixture
def flagged(conn):
    """Return the set of values in `column` produced by `view`."""
    def _flagged(view: str, column: str = "event_id") -> set:
        return {r[0] for r in conn.execute(f"SELECT {column} FROM {view}").fetchall()}
    return _flagged


@pytest.fixture
def anchors(conn):
    """Anchor event_ids for a designed anomaly class."""
    def _anchors(anomaly_class: str) -> set:
        return {r[0] for r in conn.execute(
            "SELECT event_id FROM ground_truth WHERE anomaly_class = ? AND is_anchor = 1",
            (anomaly_class,)).fetchall()}
    return _anchors
