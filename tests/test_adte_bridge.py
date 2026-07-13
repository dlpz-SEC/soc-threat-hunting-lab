"""The ADTE handoff bridge produces sane, offline, deterministic scores.

Skipped automatically when ADTE is not installed (pip install -e <adte repo>),
so the lab suite stays green standalone.
"""

import os
import sys
from pathlib import Path

import pytest

adte = pytest.importorskip("adte", reason="ADTE not installed in this venv")

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import adte_bridge  # noqa: E402

FLAGGED = {"E001", "E004", "E007", "E011", "E012", "E016", "E017"}


@pytest.fixture(scope="module")
def results():
    return adte_bridge.run()


def test_offline_pin_holds():
    # The bridge must have popped the live-intel keys at import time.
    for key in ("ADTE_ABUSEIPDB_KEY", "ADTE_VT_API_KEY", "ADTE_OTX_KEY"):
        assert key not in os.environ


def test_every_flagged_user_scored(results):
    assert set(results) == FLAGGED


def test_scores_and_verdicts_well_formed(results):
    for user, d in results.items():
        score = d["adte"]["risk_score"]
        assert isinstance(score, int) and 0 <= score <= 100, user
        assert d["adte"]["verdict"] in {"low_risk", "medium_risk", "high_risk"}, user
        # Verdict bands must agree with the score (ADTE decision_policy).
        if score < 30:
            assert d["adte"]["verdict"] == "low_risk", user
        elif score > 70:
            assert d["adte"]["verdict"] == "high_risk", user
        else:
            assert d["adte"]["verdict"] == "medium_risk", user


def test_benign_fp_scores_lowest(results):
    # E017 is the lab's deliberate benign false positive; the engine must
    # agree with ground truth and rank it at (or tied for) the bottom.
    e017 = results["E017"]["adte"]["risk_score"]
    assert e017 == min(d["adte"]["risk_score"] for d in results.values())
    assert results["E017"]["adte"]["verdict"] == "low_risk"


def test_terminated_account_outranks_benign(results):
    assert (results["E016"]["adte"]["risk_score"]
            > results["E017"]["adte"]["risk_score"])


def test_attack_campaigns_score_medium_or_higher(results):
    # The three multi-signal attacks (Tor brute force, failed brute force from
    # a scanner, terminated-account takeover) must all clear the low band.
    for user in ("E004", "E012", "E016"):
        assert results[user]["adte"]["verdict"] != "low_risk", user


def test_tor_and_scanner_named_in_rationale(results):
    def details(user):
        return " ".join(s["detail"] for s in results[user]["adte"]["rationale"])
    assert "tor-exit" in details("E004")
    assert "scanner" in details("E012")


def test_deterministic(results):
    # Same input, same engine, same numbers — the whole brand.
    again = adte_bridge.run()
    assert {u: d["adte"]["risk_score"] for u, d in results.items()} == \
           {u: d["adte"]["risk_score"] for u, d in again.items()}
