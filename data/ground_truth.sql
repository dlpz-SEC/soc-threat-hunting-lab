-- ============================================================================
-- GROUND TRUTH LABELS
-- One row per (event, anomaly_class). An event can carry multiple classes
-- (e.g. E001's CN login is both the unfamiliar-country anchor and an
-- incidental after-hours hit).
--
-- Label semantics (enforced by scripts/compute_metrics.py):
--   is_malicious : 1 if the event belongs to a planted attack, 0 if benign.
--                  PRECISION counts a flagged event as TP when it is
--                  malicious under ANY class (incidental catches are TPs).
--   is_anchor    : 1 if a correctly functioning rule for this class MUST
--                  emit this event. RECALL counts anchors of the rule's
--                  designed class only (event-grain rules).
--   campaign_id  : groups multi-event attacks. Campaign-grain rules
--                  (brute_force_failed, password_spray) measure recall per
--                  distinct campaign, not per event.
--
-- Depends on log_in_attempts (run setup_database.sql first).
-- ============================================================================

DROP TABLE IF EXISTS ground_truth;
DROP TABLE IF EXISTS ground_truth_assets;

CREATE TABLE ground_truth (
    event_id      INTEGER NOT NULL,
    is_malicious  INTEGER NOT NULL,
    anomaly_class TEXT NOT NULL,
    is_anchor     INTEGER NOT NULL DEFAULT 0,
    campaign_id   TEXT,
    notes         TEXT,
    PRIMARY KEY (event_id, anomaly_class)
);

CREATE TABLE ground_truth_assets (
    asset_id      TEXT NOT NULL,
    anomaly_class TEXT NOT NULL,
    notes         TEXT,
    PRIMARY KEY (asset_id, anomaly_class)
);

-- ----------------------------------------------------------------------------
-- Malicious events
-- ----------------------------------------------------------------------------

INSERT INTO ground_truth (event_id, is_malicious, anomaly_class, is_anchor, campaign_id, notes) VALUES
-- E001: CN excursion
(9,  1, 'unfamiliar_country', 1, NULL, 'CN not in E001 baseline [US]'),
(9,  1, 'after_hours',        0, NULL, 'incidental: 03:27 outside E001 personal window [11,16]'),
(10, 1, 'impossible_travel',  1, NULL, 'CN->US 10.8h, ~1,040 km/h required (over 900 gate). Outbound leg 8->9 was 13.3h / ~845 km/h: under the gate, borderline by velocity alone'),

-- E004: brute force with success (campaign bf-e004)
(35, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(36, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(37, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(38, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(39, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(40, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(41, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(42, 1, 'brute_force_success', 0, 'bf-e004', 'campaign member failure'),
(43, 1, 'brute_force_success', 1, 'bf-e004', 'anchor: the success event after 8 uninterrupted failures, Tor exit source'),
(43, 1, 'after_hours',         0, NULL,      'incidental: attacker success at 10:10 outside E004 personal window [12,17]'),

-- E007: DE excursion
(50, 1, 'unfamiliar_country', 1, NULL, 'DE not in E007 baseline [US]'),
(50, 1, 'after_hours',        0, NULL, 'incidental: 08:30 outside E007 personal window [11,16]'),
(51, 1, 'impossible_travel',  1, NULL, 'DE->US 4.25h, ~1,835 km/h required'),

-- E011: after-hours anchor
(67, 1, 'after_hours', 1, NULL, 'designed anchor: 02:30 vs personal window [12,16]'),

-- E016: terminated account (all three events are anchors for Rule 6)
(100, 1, 'terminated_account', 1, NULL, 'failed attempt on terminated account'),
(101, 1, 'terminated_account', 1, NULL, 'failed attempt on terminated account'),
(102, 1, 'terminated_account', 1, NULL, 'SUCCESS from RU on terminated account'),
(102, 1, 'unfamiliar_country', 0, NULL, 'incidental: no-baseline first success. Rule 6 owns this event; Rule 1 catching it is incidental'),
(102, 1, 'after_hours',        0, NULL, 'incidental: 01:30 outside Sales department window [12,17]');

-- E012: failed brute force (campaign bf-e012) — 25 member rows
INSERT INTO ground_truth (event_id, is_malicious, anomaly_class, is_anchor, campaign_id, notes)
SELECT event_id, 1, 'brute_force_failed', 0, 'bf-e012',
       '25 failures, one account, one IP, no success — brute force, not spray'
FROM log_in_attempts WHERE event_id BETWEEN 73 AND 97;

-- Password spray (campaign spray-20250116) — 25 member rows
INSERT INTO ground_truth (event_id, is_malicious, anomaly_class, is_anchor, campaign_id, notes)
SELECT event_id, 1, 'password_spray', 0, 'spray-20250116',
       'one source, 10 accounts, 2-3 attempts each, no success'
FROM log_in_attempts WHERE event_id BETWEEN 137 AND 161;

-- ----------------------------------------------------------------------------
-- Benign events with a deliberate design role
-- ----------------------------------------------------------------------------

INSERT INTO ground_truth (event_id, is_malicious, anomaly_class, is_anchor, campaign_id, notes) VALUES
(20,  0, 'benign', 0, NULL, 'tuning demonstrator: first half of US->CA 5.5h pair (~345 km/h) — old 0-12h rule would flag, velocity rule must not'),
(21,  0, 'benign', 0, NULL, 'tuning demonstrator: second half of US->CA pair; hour 19 also pins the inclusive after-hours boundary (E002 window [14,19])'),
(135, 0, 'benign_no_baseline', 0, NULL, 'EXPECTED Rule 1 false positive: dormant account first success, no geographic baseline — the honest FP that keeps precision at 0.75'),
(136, 0, 'benign_no_baseline', 0, NULL, 'second no-baseline login; Rule 1 flags only the FIRST success per no-baseline account, so this one must NOT be flagged');

-- ----------------------------------------------------------------------------
-- All remaining events are plain benign (complement, by construction).
-- tests/test_dataset.py pins the malicious/benign totals so silent data
-- edits cannot hide behind this auto-fill.
-- ----------------------------------------------------------------------------

INSERT INTO ground_truth (event_id, is_malicious, anomaly_class, is_anchor, campaign_id, notes)
SELECT l.event_id, 0, 'benign', 0, NULL, NULL
FROM log_in_attempts l
WHERE NOT EXISTS (SELECT 1 FROM ground_truth g WHERE g.event_id = l.event_id);

-- ----------------------------------------------------------------------------
-- Asset-level ground truth (Phase 4 integrity + patch posture)
-- ----------------------------------------------------------------------------

INSERT INTO ground_truth_assets (asset_id, anomaly_class, notes) VALUES
('DEV-099', 'orphan_device',       'listed owner E999 does not exist in the employee directory'),
('DEV-011', 'inventory_mismatch',  'primary owner E011 vs backup owner E007 — and E007 is the impossible-travel subject: containment on the wrong inventory isolates the wrong device'),
('SRV-001', 'critical_patch_age',  '285 days since patch at asof_date 2025-01-20'),
('DEV-011', 'critical_patch_age',  '245 days since patch at asof_date'),
('DEV-012', 'critical_patch_age',  '219 days since patch at asof_date'),
('E017',    'user_without_device', 'active employee with no assigned device'),
('E018',    'user_without_device', 'active employee with no assigned device'),
('E019',    'user_without_device', 'active employee with no assigned device'),
('E020',    'user_without_device', 'active employee with no assigned device');
