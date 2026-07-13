"""The measured metrics match the numbers the docs claim.

Pins the honest story: full recall, one deliberate false positive.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import compute_metrics as cm  # noqa: E402


def _by_key(conn):
    return {m.spec.key: m for m in cm.compute(conn)}


def test_every_rule_has_full_recall(conn):
    for m in cm.compute(conn):
        assert m.recall == 1.0, f"{m.spec.key} missed a designed anchor (recall {m.recall})"


def test_unfamiliar_country_has_one_deliberate_fp(conn):
    m = _by_key(conn)["unfamiliar_country"]
    assert m.fp == 1
    assert "135" in m.fp_events          # the E017 dormant-account FP
    assert m.precision == 0.75


def test_terminated_and_travel_rules_are_precise(conn):
    metrics = _by_key(conn)
    assert metrics["inactive_account"].precision == 1.0
    assert metrics["impossible_travel"].precision == 1.0
    assert metrics["brute_force"].precision == 1.0


def test_overall_precision_recall(conn):
    metrics = cm.compute(conn)
    tp = sum(m.tp for m in metrics)
    fp = sum(m.fp for m in metrics)
    flagged = sum(m.flagged for m in metrics)
    assert fp == 1                       # exactly the one designed FP
    assert tp / flagged >= 0.90          # micro precision >= 0.90


def test_dataset_summary_counts(conn):
    s = cm.dataset_summary(conn)
    assert s["events"] == 161
    assert s["employees"] == 22
    assert s["integrity_issues"] == 6    # 1 orphan + 1 mismatch + 4 without-device
    assert s["critical_patch"] == 3
