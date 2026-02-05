-- ============================================================================
-- SOC THREAT HUNTING LAB: DETECTION QUERIES
-- All queries tested against SQLite - adjust for MariaDB/MySQL as needed
-- ============================================================================

-- ============================================================================
-- PHASE 1: BASELINE ENUMERATION
-- Purpose: Establish "known normal" before hunting anomalies
-- ============================================================================

-- 1.1 Geographic baseline: Known login countries per user
-- This becomes our allowlist for detecting unfamiliar locations
CREATE VIEW IF NOT EXISTS v_user_country_baseline AS
SELECT 
    username,
    GROUP_CONCAT(DISTINCT country) AS known_countries,
    COUNT(DISTINCT country) AS country_count
FROM log_in_attempts
WHERE success = 1
  AND login_date < '2025-01-13'  -- Use first week as baseline period
GROUP BY username;

-- 1.2 Login time distribution: Normal working hours
CREATE VIEW IF NOT EXISTS v_hourly_distribution AS
SELECT 
    CAST(SUBSTR(login_time, 1, 2) AS INTEGER) AS login_hour,
    COUNT(*) AS login_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM log_in_attempts WHERE success = 1), 1) AS pct
FROM log_in_attempts
WHERE success = 1
GROUP BY login_hour
ORDER BY login_hour;

-- 1.3 Endpoint patch posture baseline
CREATE VIEW IF NOT EXISTS v_patch_status AS
SELECT 
    m.device_id,
    m.employee_id,
    e.first_name || ' ' || e.last_name AS owner_name,
    e.department,
    m.operating_system,
    m.os_patch_date,
    CAST(julianday('2025-01-20') - julianday(m.os_patch_date) AS INTEGER) AS days_since_patch,
    CASE 
        WHEN julianday('2025-01-20') - julianday(m.os_patch_date) > 180 THEN 'CRITICAL'
        WHEN julianday('2025-01-20') - julianday(m.os_patch_date) > 90 THEN 'WARNING'
        ELSE 'OK'
    END AS patch_risk
FROM machines m
LEFT JOIN employees e ON m.employee_id = e.employee_id
ORDER BY days_since_patch DESC;


-- ============================================================================
-- PHASE 2: ANOMALY DETECTION RULES
-- Purpose: Identify deviations from baseline
-- ============================================================================

-- RULE 1: Unfamiliar Country Login (HIGH severity)
-- Detects successful logins from countries not in user's baseline
CREATE VIEW IF NOT EXISTS v_detect_unfamiliar_country AS
SELECT 
    l.event_id,
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.country AS anomaly_country,
    b.known_countries AS baseline_countries,
    l.source_ip,
    'HIGH' AS severity,
    'Unfamiliar login location: ' || l.country || ' not in baseline [' || COALESCE(b.known_countries, 'NONE') || ']' AS reason
FROM log_in_attempts l
LEFT JOIN v_user_country_baseline b ON l.username = b.username
LEFT JOIN employees e ON l.username = e.employee_id
WHERE l.success = 1
  AND l.login_date >= '2025-01-13'  -- Detection period (after baseline)
  AND (b.known_countries IS NULL 
       OR INSTR(',' || b.known_countries || ',', ',' || l.country || ',') = 0);


-- RULE 2: Impossible Travel (HIGH severity)
-- Detects same user logging in from different countries within impossible timeframe
CREATE VIEW IF NOT EXISTS v_detect_impossible_travel AS
SELECT 
    a.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    a.login_date || ' ' || a.login_time AS timestamp_1,
    a.country AS country_1,
    a.source_ip AS ip_1,
    b.login_date || ' ' || b.login_time AS timestamp_2,
    b.country AS country_2,
    b.source_ip AS ip_2,
    ROUND((julianday(b.login_date || ' ' || b.login_time) - 
           julianday(a.login_date || ' ' || a.login_time)) * 24, 1) AS hours_apart,
    'HIGH' AS severity,
    'Impossible travel: ' || a.country || ' → ' || b.country || ' in ' || 
        ROUND((julianday(b.login_date || ' ' || b.login_time) - 
               julianday(a.login_date || ' ' || a.login_time)) * 24, 1) || ' hours' AS reason
FROM log_in_attempts a
JOIN log_in_attempts b ON a.username = b.username
    AND a.event_id < b.event_id
    AND a.success = 1 AND b.success = 1
    AND a.country != b.country
LEFT JOIN employees e ON a.username = e.employee_id
WHERE (julianday(b.login_date || ' ' || b.login_time) - 
       julianday(a.login_date || ' ' || a.login_time)) * 24 BETWEEN 0 AND 12
  AND a.login_date >= '2025-01-13';


-- RULE 3: After-Hours Login (MEDIUM severity)
-- Detects logins outside normal business hours (before 06:00 or after 20:00 UTC)
CREATE VIEW IF NOT EXISTS v_detect_after_hours AS
SELECT 
    l.event_id,
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date || ' ' || l.login_time AS timestamp,
    CAST(SUBSTR(l.login_time, 1, 2) AS INTEGER) AS login_hour,
    l.country,
    l.source_ip,
    CASE 
        WHEN e.department IN ('IT Security', 'IT Infrastructure') THEN 'LOW'
        ELSE 'MEDIUM'
    END AS severity,
    'After-hours login at ' || l.login_time || ' UTC' AS reason
FROM log_in_attempts l
LEFT JOIN employees e ON l.username = e.employee_id
WHERE l.success = 1
  AND (CAST(SUBSTR(l.login_time, 1, 2) AS INTEGER) < 6 
       OR CAST(SUBSTR(l.login_time, 1, 2) AS INTEGER) > 20)
  AND l.username NOT LIKE 'svc_%'  -- Exclude service accounts
  AND l.login_date >= '2025-01-13';


-- RULE 4: Brute Force - Multiple Failures then Success (HIGH severity)
-- Detects password guessing that eventually succeeded
CREATE VIEW IF NOT EXISTS v_detect_brute_force AS
SELECT 
    s.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    MIN(f.login_date || ' ' || f.login_time) AS first_failure,
    s.login_date || ' ' || s.login_time AS success_time,
    COUNT(f.event_id) AS failure_count,
    s.source_ip AS success_ip,
    'HIGH' AS severity,
    'Brute force: ' || COUNT(f.event_id) || ' failures preceding success from ' || s.source_ip AS reason
FROM log_in_attempts s
JOIN log_in_attempts f ON s.username = f.username
    AND f.success = 0
    AND julianday(s.login_date || ' ' || s.login_time) - 
        julianday(f.login_date || ' ' || f.login_time) BETWEEN 0 AND 0.042  -- Within ~1 hour
LEFT JOIN employees e ON s.username = e.employee_id
WHERE s.success = 1
GROUP BY s.username, s.event_id
HAVING COUNT(f.event_id) >= 5;


-- RULE 5: Password Spray - Excessive Failures (MEDIUM severity)
-- Detects accounts targeted by mass password guessing
CREATE VIEW IF NOT EXISTS v_detect_password_spray AS
SELECT 
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date,
    COUNT(*) AS failure_count,
    GROUP_CONCAT(DISTINCT l.source_ip) AS source_ips,
    MIN(l.login_time) AS first_attempt,
    MAX(l.login_time) AS last_attempt,
    'MEDIUM' AS severity,
    'Password spray: ' || COUNT(*) || ' failed attempts on ' || l.login_date AS reason
FROM log_in_attempts l
LEFT JOIN employees e ON l.username = e.employee_id
WHERE l.success = 0
GROUP BY l.username, l.login_date
HAVING COUNT(*) >= 10;


-- RULE 6: Inactive Account Activity (HIGH severity)
-- Detects any login attempts on terminated/disabled accounts
CREATE VIEW IF NOT EXISTS v_detect_inactive_account AS
SELECT 
    l.event_id,
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.status AS account_status,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.country,
    l.source_ip,
    CASE WHEN l.success = 1 THEN 'SUCCESS' ELSE 'FAILED' END AS outcome,
    'HIGH' AS severity,
    CASE 
        WHEN l.success = 1 THEN 'CRITICAL: Successful login on ' || e.status || ' account from ' || l.country
        ELSE 'Login attempt on ' || e.status || ' account from ' || l.country
    END AS reason
FROM log_in_attempts l
JOIN employees e ON l.username = e.employee_id
WHERE e.status != 'Active';


-- ============================================================================
-- PHASE 3: UNIFIED TRIAGE QUEUE
-- Combines all detections with priority scoring
-- ============================================================================

CREATE VIEW IF NOT EXISTS v_triage_queue AS
SELECT 
    'UNFAMILIAR_COUNTRY' AS detection_type,
    username, user_name, department, timestamp, severity, reason
FROM v_detect_unfamiliar_country
UNION ALL
SELECT 
    'IMPOSSIBLE_TRAVEL' AS detection_type,
    username, user_name, department, timestamp_1 AS timestamp, severity, reason
FROM v_detect_impossible_travel
UNION ALL
SELECT 
    'AFTER_HOURS' AS detection_type,
    username, user_name, department, timestamp, severity, reason
FROM v_detect_after_hours
UNION ALL
SELECT 
    'BRUTE_FORCE' AS detection_type,
    username, user_name, department, success_time AS timestamp, severity, reason
FROM v_detect_brute_force
UNION ALL
SELECT 
    'PASSWORD_SPRAY' AS detection_type,
    username, user_name, department, login_date || ' ' || first_attempt AS timestamp, severity, reason
FROM v_detect_password_spray
UNION ALL
SELECT 
    'INACTIVE_ACCOUNT' AS detection_type,
    username, user_name, account_status AS department, timestamp, severity, reason
FROM v_detect_inactive_account
ORDER BY 
    CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
    timestamp DESC;


-- ============================================================================
-- PHASE 4: INTEGRITY VALIDATION
-- Verify data consistency before taking action
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
