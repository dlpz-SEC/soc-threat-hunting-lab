-- ============================================================================
-- SOC THREAT HUNTING LAB: DETECTION QUERIES
-- All queries tested against SQLite (3.28+ for window functions).
--
-- Conventions:
--   * No hardcoded dates/thresholds — views read hunt_config via scalar
--     subqueries (SQLite views cannot take parameters).
--   * Baseline period:  login_date <  hunt_config.baseline_end
--   * Detection period: login_date >= hunt_config.detection_start
--   * Every event-grain detection row carries the event_id it anchors on;
--     campaign-grain rows (spray, failed brute force) carry a campaign_key.
-- ============================================================================

-- ============================================================================
-- PHASE 0: HELPERS
-- ============================================================================

-- Single source for timestamp math; kills repeated concat/julianday noise.
CREATE VIEW IF NOT EXISTS v_login_events AS
SELECT
    event_id, username, login_date, login_time, country, success, source_ip,
    julianday(login_date || ' ' || login_time) AS ts,
    CAST(SUBSTR(login_time, 1, 2) AS INTEGER) AS login_hour
FROM log_in_attempts;

-- Static-intel join for login sources. The LIKE-prefix match is safe ONLY
-- because every seeded range sits on a /24 (or /16) octet boundary;
-- production code compares integer ranges (see ADTE's ipaddress usage).
CREATE VIEW IF NOT EXISTS v_ip_enrichment AS
SELECT
    l.event_id, l.source_ip,
    ie.cidr, ie.is_malicious, ie.confidence, ie.source, ie.tags
FROM log_in_attempts l
JOIN ip_enrichment ie ON l.source_ip LIKE ie.ip_prefix || '%';

-- ============================================================================
-- PHASE 1: BASELINE ENUMERATION
-- Purpose: Establish "known normal" before hunting anomalies
-- ============================================================================

-- 1.1 Geographic baseline, normalized: one row per (username, country).
-- Replaces the old GROUP_CONCAT-CSV + INSTR membership test, which was a
-- fragile string hack.
CREATE VIEW IF NOT EXISTS v_user_country_baseline AS
SELECT DISTINCT username, country
FROM log_in_attempts
WHERE success = 1
  AND login_date < (SELECT value FROM hunt_config WHERE key = 'baseline_end');

-- Display variant for reports (the old concatenated shape).
CREATE VIEW IF NOT EXISTS v_user_country_baseline_display AS
SELECT username,
       GROUP_CONCAT(country, ',') AS known_countries,
       COUNT(*) AS country_count
FROM v_user_country_baseline
GROUP BY username;

-- 1.2 Login time distribution across the org (context/report view).
CREATE VIEW IF NOT EXISTS v_hourly_distribution AS
SELECT login_hour,
       COUNT(*) AS login_count,
       ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM v_login_events WHERE success = 1), 1) AS pct
FROM v_login_events
WHERE success = 1
GROUP BY login_hour
ORDER BY login_hour;

-- 1.3 Per-user login-hour baseline (feeds Rule 3). Same baselining idea as
-- the geographic allowlist, applied to hours.
CREATE VIEW IF NOT EXISTS v_user_hour_baseline AS
SELECT username,
       COUNT(*) AS baseline_logins,
       MIN(login_hour) AS min_hour,
       MAX(login_hour) AS max_hour
FROM v_login_events
WHERE success = 1
  AND login_date < (SELECT value FROM hunt_config WHERE key = 'baseline_end')
GROUP BY username;

-- Department fallback for users with a thin personal baseline.
-- Service accounts are excluded: their 00:00/02:00 batch logins would blow
-- the IT Infrastructure window wide open.
CREATE VIEW IF NOT EXISTS v_dept_hour_baseline AS
SELECT e.department,
       COUNT(*) AS baseline_logins,
       MIN(l.login_hour) AS min_hour,
       MAX(l.login_hour) AS max_hour
FROM v_login_events l
JOIN employees e ON l.username = e.employee_id
WHERE l.success = 1
  AND l.username NOT LIKE 'svc_%'
  AND l.login_date < (SELECT value FROM hunt_config WHERE key = 'baseline_end')
GROUP BY e.department;

-- Effective hour window per user: personal baseline when it has enough
-- samples, else department, else the global 06-20 default. baseline_source
-- makes the provenance visible in every detection row.
CREATE VIEW IF NOT EXISTS v_hour_windows AS
SELECT e.employee_id AS username,
       CASE WHEN ub.baseline_logins >= ms.v THEN 'user'
            WHEN db.baseline_logins >= ms.v THEN 'department'
            ELSE 'global-default' END AS baseline_source,
       CASE WHEN ub.baseline_logins >= ms.v THEN ub.min_hour - tol.v
            WHEN db.baseline_logins >= ms.v THEN db.min_hour - tol.v
            ELSE 6 END AS window_start,
       CASE WHEN ub.baseline_logins >= ms.v THEN ub.max_hour + tol.v
            WHEN db.baseline_logins >= ms.v THEN db.max_hour + tol.v
            ELSE 20 END AS window_end
FROM employees e
LEFT JOIN v_user_hour_baseline ub ON ub.username = e.employee_id
LEFT JOIN v_dept_hour_baseline db ON db.department = e.department
CROSS JOIN (SELECT CAST(value AS INTEGER) AS v FROM hunt_config WHERE key = 'hour_baseline_min_samples') ms
CROSS JOIN (SELECT CAST(value AS INTEGER) AS v FROM hunt_config WHERE key = 'hour_tolerance') tol;

-- 1.4 Endpoint patch posture baseline ("now" = hunt_config.asof_date).
CREATE VIEW IF NOT EXISTS v_patch_status AS
SELECT
    m.device_id,
    m.employee_id,
    e.first_name || ' ' || e.last_name AS owner_name,
    e.department,
    m.operating_system,
    m.os_patch_date,
    CAST(julianday((SELECT value FROM hunt_config WHERE key = 'asof_date'))
         - julianday(m.os_patch_date) AS INTEGER) AS days_since_patch,
    CASE
        WHEN julianday((SELECT value FROM hunt_config WHERE key = 'asof_date'))
             - julianday(m.os_patch_date) > 180 THEN 'CRITICAL'
        WHEN julianday((SELECT value FROM hunt_config WHERE key = 'asof_date'))
             - julianday(m.os_patch_date) > 90 THEN 'WARNING'
        ELSE 'OK'
    END AS patch_risk
FROM machines m
LEFT JOIN employees e ON m.employee_id = e.employee_id
ORDER BY days_since_patch DESC;

-- ============================================================================
-- PHASE 2: ANOMALY DETECTION RULES
-- ============================================================================

-- RULE 1: Unfamiliar Country Login                       MITRE ATT&CK: T1078
-- Two explicit branches:
--   (a) users WITH a geographic baseline: flag successes from countries not
--       in the allowlist. High-risk countries upgrade to HIGH (lifted from
--       playbook AUTH-004's severity-adjustment table).
--   (b) users WITHOUT any baseline (new or dormant accounts): flag only the
--       FIRST observed success — a one-time "account became active" signal,
--       not a per-login alarm. This branch deliberately separates
--       new-hire/dormant accounts from the terminated-account case, which
--       Rule 6 owns (Rule 1 also seeing E016 is incidental).
CREATE VIEW IF NOT EXISTS v_detect_unfamiliar_country AS
SELECT
    l.event_id,
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.country AS anomaly_country,
    d.known_countries AS baseline_countries,
    l.source_ip,
    'baseline' AS baseline_state,
    CASE WHEN l.country IN ('RU', 'CN', 'KP', 'IR') THEN 'HIGH' ELSE 'MEDIUM' END AS severity,
    'Unfamiliar login location: ' || l.country || ' not in baseline ['
        || d.known_countries || ']' AS reason
FROM v_login_events l
JOIN v_user_country_baseline_display d ON l.username = d.username
LEFT JOIN employees e ON l.username = e.employee_id
WHERE l.success = 1
  AND l.login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start')
  AND NOT EXISTS (SELECT 1 FROM v_user_country_baseline b
                  WHERE b.username = l.username AND b.country = l.country)
UNION ALL
SELECT
    l.event_id,
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.country AS anomaly_country,
    NULL AS baseline_countries,
    l.source_ip,
    'no_baseline' AS baseline_state,
    CASE WHEN l.country IN ('RU', 'CN', 'KP', 'IR') THEN 'HIGH' ELSE 'MEDIUM' END AS severity,
    'No geographic baseline (new or dormant account): first observed success from '
        || l.country AS reason
FROM v_login_events l
LEFT JOIN employees e ON l.username = e.employee_id
WHERE l.success = 1
  AND l.login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start')
  AND NOT EXISTS (SELECT 1 FROM v_user_country_baseline b WHERE b.username = l.username)
  AND l.ts = (SELECT MIN(l2.ts) FROM v_login_events l2
              WHERE l2.username = l.username AND l2.success = 1);


-- RULE 2: Impossible Travel                              MITRE ATT&CK: T1078
-- LAG over successes per user, velocity-gated against precomputed
-- country-centroid distances. Flags a transition only when the REQUIRED
-- velocity exceeds hunt_config.max_travel_speed_kmh (900 ~ commercial
-- cruise speed) — "different country within N hours" alone is not evidence.
-- required_kmh is exposed so borderline cases stay visible as numbers.
-- Pairs in travel_exceptions (US<->CA corridor) are DOWNGRADED to MEDIUM,
-- never suppressed.
-- Scale note: the previous self-join was O(n^2) per user — harmless at 161
-- rows, quietly catastrophic at SIEM scale. LAG is one ordered pass, and
-- each detection row anchors exactly one event_id (the arrival leg).
CREATE VIEW IF NOT EXISTS v_travel_transitions AS
SELECT
    event_id, username, login_date, login_time, country, source_ip, ts,
    LAG(event_id)   OVER w AS prev_event_id,
    LAG(country)    OVER w AS prev_country,
    LAG(ts)         OVER w AS prev_ts,
    LAG(source_ip)  OVER w AS prev_ip,
    LAG(login_date) OVER w AS prev_login_date,
    LAG(login_time) OVER w AS prev_login_time
FROM v_login_events
WHERE success = 1
WINDOW w AS (PARTITION BY username ORDER BY ts);

CREATE VIEW IF NOT EXISTS v_detect_impossible_travel AS
SELECT
    t.event_id,
    t.prev_event_id,
    t.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    t.prev_login_date || ' ' || t.prev_login_time AS timestamp_1,
    t.prev_country AS country_1,
    t.prev_ip AS ip_1,
    t.login_date || ' ' || t.login_time AS timestamp_2,
    t.country AS country_2,
    t.source_ip AS ip_2,
    ROUND((t.ts - t.prev_ts) * 24, 1) AS hours_apart,
    d.distance_km,
    -- MAX(delta, 1 minute) guards divide-by-zero on same-timestamp pairs;
    -- a zero-time cross-country pair should flag (infinite velocity), not
    -- vanish into a NULL comparison.
    CAST(ROUND(d.distance_km / MAX((t.ts - t.prev_ts) * 24.0, 1.0 / 60.0)) AS INTEGER) AS required_kmh,
    CASE WHEN x.rationale IS NOT NULL THEN 'MEDIUM' ELSE 'HIGH' END AS severity,
    'Impossible travel: ' || t.prev_country || ' -> ' || t.country || ' in '
        || ROUND((t.ts - t.prev_ts) * 24, 1) || 'h requires ~'
        || CAST(ROUND(d.distance_km / MAX((t.ts - t.prev_ts) * 24.0, 1.0 / 60.0)) AS INTEGER)
        || ' km/h (gate: ' || (SELECT value FROM hunt_config WHERE key = 'max_travel_speed_kmh')
        || ' km/h)'
        || COALESCE(' [exception: ' || x.rationale || ']', '') AS reason
FROM v_travel_transitions t
JOIN country_distance d
  ON d.country_a = MIN(t.country, t.prev_country)
 AND d.country_b = MAX(t.country, t.prev_country)
LEFT JOIN travel_exceptions x
  ON x.country_a = MIN(t.country, t.prev_country)
 AND x.country_b = MAX(t.country, t.prev_country)
LEFT JOIN employees e ON t.username = e.employee_id
WHERE t.prev_country IS NOT NULL
  AND t.country != t.prev_country
  AND d.distance_km / MAX((t.ts - t.prev_ts) * 24.0, 1.0 / 60.0)
      > CAST((SELECT value FROM hunt_config WHERE key = 'max_travel_speed_kmh') AS REAL)
  AND t.login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start');


-- RULE 3: After-Hours Login                              MITRE ATT&CK: T1078
-- Baselined, not hardcoded: each user gets a personal hour window
-- (observed baseline min/max hour +/- tolerance) when their baseline has
-- enough samples, else the department window, else the global 06-20
-- default. baseline_source shows which tier fired. Window bounds are
-- INCLUSIVE (hour == bound passes). Weak signal on its own — severity
-- never exceeds MEDIUM; it earns its keep corroborating other rules.
CREATE VIEW IF NOT EXISTS v_detect_after_hours AS
SELECT
    l.event_id,
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.login_hour,
    l.country,
    l.source_ip,
    w.baseline_source,
    w.window_start,
    w.window_end,
    CASE WHEN e.department IN ('IT Security', 'IT Infrastructure') THEN 'LOW'
         ELSE 'MEDIUM' END AS severity,
    'Login at ' || l.login_time || ' UTC outside ' || w.baseline_source
        || ' hour window [' || w.window_start || ':00-' || w.window_end || ':59]' AS reason
FROM v_login_events l
JOIN employees e ON l.username = e.employee_id
JOIN v_hour_windows w ON w.username = l.username
WHERE l.success = 1
  AND l.username NOT LIKE 'svc_%'  -- service accounts run at fixed odd hours by design
  AND l.login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start')
  AND (l.login_hour < w.window_start OR l.login_hour > w.window_end);


-- RULE 4: Brute Force - Failures then Success        MITRE ATT&CK: T1110.001
-- A failure counts toward a success only when NO success intervenes between
-- them (NOT EXISTS). This fixes two defects in the previous version: a
-- single failure could be counted against multiple later successes, and
-- "consecutive failures" was claimed but never enforced. Also adds the
-- detection-window filter the old view silently lacked.
CREATE VIEW IF NOT EXISTS v_detect_brute_force AS
SELECT
    s.event_id,
    s.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    MIN(f.login_date || ' ' || f.login_time) AS first_failure,
    s.login_date || ' ' || s.login_time AS success_time,
    COUNT(f.event_id) AS failure_count,
    s.source_ip AS success_ip,
    'HIGH' AS severity,
    'Brute force: ' || COUNT(f.event_id) || ' uninterrupted failures within '
        || (SELECT value FROM hunt_config WHERE key = 'bf_window_minutes')
        || ' min preceding success from ' || s.source_ip AS reason
FROM v_login_events s
JOIN v_login_events f
  ON f.username = s.username
 AND f.success = 0
 AND f.ts <= s.ts
 AND (s.ts - f.ts) * 1440.0
     <= CAST((SELECT value FROM hunt_config WHERE key = 'bf_window_minutes') AS REAL)
 AND NOT EXISTS (SELECT 1 FROM v_login_events m
                 WHERE m.username = s.username
                   AND m.success = 1
                   AND m.ts > f.ts AND m.ts < s.ts)
LEFT JOIN employees e ON s.username = e.employee_id
WHERE s.success = 1
  AND s.login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start')
GROUP BY s.event_id, s.username
HAVING COUNT(f.event_id) >=
       CAST((SELECT value FROM hunt_config WHERE key = 'bf_min_failures') AS INTEGER);


-- RULE 5a: Password Spray - One Source, Many Accounts  MITRE ATT&CK: T1110.003
-- A spray is one SOURCE walking many ACCOUNTS with few attempts each — the
-- previous per-account GROUP BY could never see one. Grouped by
-- (source_ip, login_date); fires on distinct failed accounts >= threshold.
-- A spray source that also scored a success upgrades to HIGH.
CREATE VIEW IF NOT EXISTS v_detect_password_spray AS
SELECT
    l.source_ip,
    l.login_date,
    COUNT(DISTINCT CASE WHEN l.success = 0 THEN l.username END) AS accounts_targeted,
    SUM(CASE WHEN l.success = 0 THEN 1 ELSE 0 END) AS total_failures,
    SUM(l.success) AS successes,
    GROUP_CONCAT(DISTINCT l.username) AS usernames,
    MIN(l.login_time) AS first_attempt,
    MAX(l.login_time) AS last_attempt,
    l.source_ip || '|' || l.login_date AS campaign_key,
    CASE WHEN SUM(l.success) > 0 THEN 'HIGH' ELSE 'MEDIUM' END AS severity,
    'Password spray: ' || COUNT(DISTINCT CASE WHEN l.success = 0 THEN l.username END)
        || ' accounts, ' || SUM(CASE WHEN l.success = 0 THEN 1 ELSE 0 END)
        || ' failures from ' || l.source_ip || ' on ' || l.login_date
        || CASE WHEN SUM(l.success) > 0
                THEN ' - INCLUDES ' || SUM(l.success) || ' SUCCESS(ES)' ELSE '' END AS reason
FROM v_login_events l
WHERE l.login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start')
GROUP BY l.source_ip, l.login_date
HAVING COUNT(DISTINCT CASE WHEN l.success = 0 THEN l.username END) >=
       CAST((SELECT value FROM hunt_config WHERE key = 'spray_min_accounts') AS INTEGER);


-- RULE 5b: Failed Brute Force - One Account, No Success  MITRE ATT&CK: T1110.001
-- E012's home. 25 failures against one account from one IP is brute force
-- that never succeeded — NOT a spray. Kept separate from Rule 4 (which
-- requires a success) and Rule 5a (which requires many accounts).
CREATE VIEW IF NOT EXISTS v_detect_bruteforce_failed AS
SELECT
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date,
    l.source_ip,
    COUNT(*) AS failure_count,
    MIN(l.login_time) AS first_attempt,
    MAX(l.login_time) AS last_attempt,
    l.username || '|' || l.source_ip || '|' || l.login_date AS campaign_key,
    'MEDIUM' AS severity,
    'Failed brute force: ' || COUNT(*) || ' failures on one account from '
        || l.source_ip || ' on ' || l.login_date || ', no success from that source' AS reason
FROM v_login_events l
LEFT JOIN employees e ON l.username = e.employee_id
WHERE l.success = 0
  AND l.login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start')
GROUP BY l.username, l.source_ip, l.login_date
HAVING COUNT(*) >=
       CAST((SELECT value FROM hunt_config WHERE key = 'bf_failed_min_failures') AS INTEGER)
   AND NOT EXISTS (SELECT 1 FROM v_login_events s
                   WHERE s.username = l.username
                     AND s.source_ip = l.source_ip
                     AND s.login_date = l.login_date
                     AND s.success = 1);


-- RULE 6: Inactive Account Activity                  MITRE ATT&CK: T1078.002
-- Deliberately NO detection-window filter and NO success filter: ANY
-- activity on a non-Active account matters, whenever it happened. This is
-- the rule that owns E016; other rules seeing E016's events is incidental.
CREATE VIEW IF NOT EXISTS v_detect_inactive_account AS
SELECT
    l.event_id,
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    e.status AS account_status,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.country,
    l.source_ip,
    CASE WHEN l.success = 1 THEN 'SUCCESS' ELSE 'FAILED' END AS outcome,
    'HIGH' AS severity,
    CASE
        WHEN l.success = 1 THEN 'CRITICAL: Successful login on ' || e.status
            || ' account from ' || l.country
        ELSE 'Login attempt on ' || e.status || ' account from ' || l.country
    END AS reason
FROM log_in_attempts l
JOIN employees e ON l.username = e.employee_id
WHERE e.status != 'Active';


-- ============================================================================
-- PHASE 3: UNIFIED TRIAGE QUEUE
-- Every row: ATT&CK technique + static-intel enrichment on the source IP.
-- Event-grain rows carry event_id; campaign-grain rows carry campaign_key.
-- ============================================================================

CREATE VIEW IF NOT EXISTS v_triage_queue AS
SELECT
    q.detection_type, q.event_id, q.campaign_key, q.username, q.user_name,
    q.department, q.timestamp, q.source_ip, q.severity, q.mitre_technique,
    q.reason,
    ie.source AS intel_source, ie.tags AS intel_tags, ie.confidence AS intel_confidence
FROM (
    SELECT 'UNFAMILIAR_COUNTRY' AS detection_type, event_id, NULL AS campaign_key,
           username, user_name, department, timestamp, source_ip, severity,
           'T1078' AS mitre_technique, reason
    FROM v_detect_unfamiliar_country
    UNION ALL
    SELECT 'IMPOSSIBLE_TRAVEL', event_id, NULL, username, user_name, department,
           timestamp_2, ip_2, severity, 'T1078', reason
    FROM v_detect_impossible_travel
    UNION ALL
    SELECT 'AFTER_HOURS', event_id, NULL, username, user_name, department,
           timestamp, source_ip, severity, 'T1078', reason
    FROM v_detect_after_hours
    UNION ALL
    SELECT 'BRUTE_FORCE', event_id, NULL, username, user_name, department,
           success_time, success_ip, severity, 'T1110.001', reason
    FROM v_detect_brute_force
    UNION ALL
    SELECT 'PASSWORD_SPRAY', NULL, campaign_key, NULL, NULL, NULL,
           login_date || ' ' || first_attempt, source_ip, severity, 'T1110.003', reason
    FROM v_detect_password_spray
    UNION ALL
    SELECT 'BRUTEFORCE_FAILED', NULL, campaign_key, username, user_name, department,
           login_date || ' ' || first_attempt, source_ip, severity, 'T1110.001', reason
    FROM v_detect_bruteforce_failed
    UNION ALL
    SELECT 'INACTIVE_ACCOUNT', event_id, NULL, username, user_name, department,
           timestamp, source_ip, severity, 'T1078.002', reason
    FROM v_detect_inactive_account
) q
LEFT JOIN ip_enrichment ie ON q.source_ip LIKE ie.ip_prefix || '%'
ORDER BY
    CASE q.severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
    q.timestamp DESC;


-- ============================================================================
-- PHASE 4: INTEGRITY VALIDATION
-- Verify data consistency before taking action. Containment decisions made
-- on a corrupt inventory can isolate the wrong device.
-- ============================================================================

-- 4.1 Orphan devices (no valid owner)
CREATE VIEW IF NOT EXISTS v_orphan_devices AS
SELECT
    m.device_id,
    m.employee_id AS listed_owner,
    m.operating_system,
    m.os_patch_date,
    'Device has no valid owner in employee directory' AS issue
FROM machines m
LEFT JOIN employees e ON m.employee_id = e.employee_id
WHERE e.employee_id IS NULL;

-- 4.2 Inventory mismatch (primary vs backup disagree)
CREATE VIEW IF NOT EXISTS v_inventory_mismatch AS
SELECT
    m.device_id,
    m.employee_id AS primary_owner,
    ep.first_name || ' ' || ep.last_name AS primary_owner_name,
    b.employee_id AS backup_owner,
    eb.first_name || ' ' || eb.last_name AS backup_owner_name,
    'Ownership conflict between inventories' AS issue
FROM machines m
JOIN machines_backup b ON m.device_id = b.device_id
LEFT JOIN employees ep ON m.employee_id = ep.employee_id
LEFT JOIN employees eb ON b.employee_id = eb.employee_id
WHERE m.employee_id != b.employee_id;

-- 4.3 Active users without devices
CREATE VIEW IF NOT EXISTS v_users_without_devices AS
SELECT
    e.employee_id,
    e.first_name || ' ' || e.last_name AS employee_name,
    e.department,
    e.status,
    'Active employee has no assigned device' AS issue
FROM employees e
LEFT JOIN machines m ON e.employee_id = m.employee_id
WHERE e.status = 'Active'
  AND m.device_id IS NULL
  AND e.employee_id NOT LIKE 'svc_%';
