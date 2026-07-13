-- ============================================================================
-- SOC THREAT HUNTING LAB: SYNTHETIC DATASET
-- Purpose: Realistic enterprise security telemetry with embedded anomalies
-- Database: SQLite (portable) or MariaDB compatible
--
-- Every log_in_attempts row carries an EXPLICIT event_id so that
-- data/ground_truth.sql can label each event durably. tests/test_dataset.py
-- enforces full label coverage. Do not add rows without ids + labels.
-- ============================================================================

-- Clean slate
DROP TABLE IF EXISTS log_in_attempts;
DROP TABLE IF EXISTS machines;
DROP TABLE IF EXISTS machines_backup;
DROP TABLE IF EXISTS employees;
DROP TABLE IF EXISTS hunt_config;

-- ============================================================================
-- SCHEMA DEFINITION
-- ============================================================================

CREATE TABLE employees (
    employee_id VARCHAR(32) PRIMARY KEY,
    first_name VARCHAR(64),
    last_name VARCHAR(64),
    department VARCHAR(64),
    office VARCHAR(64),
    status VARCHAR(16),
    hire_date DATE
);

CREATE TABLE log_in_attempts (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(32) NOT NULL,
    login_date DATE NOT NULL,
    login_time TIME NOT NULL,
    country VARCHAR(8) NOT NULL,
    success INTEGER NOT NULL,
    source_ip VARCHAR(45)
);

CREATE TABLE machines (
    device_id VARCHAR(32) PRIMARY KEY,
    employee_id VARCHAR(32),
    operating_system VARCHAR(64),
    os_patch_date DATE,
    device_type VARCHAR(32),
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE machines_backup (
    device_id VARCHAR(32) PRIMARY KEY,
    employee_id VARCHAR(32)
);

-- ============================================================================
-- HUNT CONFIGURATION
-- SQLite views cannot take parameters; detection views read these values via
-- scalar subqueries instead of hardcoded literals. Change the hunt window or
-- thresholds here, in one place.
-- ============================================================================

CREATE TABLE hunt_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO hunt_config (key, value) VALUES
    ('baseline_end',              '2025-01-13'),  -- baseline = login_date < this
    ('detection_start',           '2025-01-13'),  -- detections = login_date >= this
    ('asof_date',                 '2025-01-20'),  -- "now" for patch-age math
    ('bf_window_minutes',         '60'),          -- brute force: failure lookback before a success
    ('bf_min_failures',           '5'),           -- brute force: minimum uninterrupted failures
    ('bf_failed_min_failures',    '10'),          -- failed brute force: per-account failures/day
    ('spray_min_accounts',        '5'),           -- spray: distinct accounts per source IP per day
    ('hour_baseline_min_samples', '5'),           -- after-hours: min baseline logins to trust a user window
    ('hour_tolerance',            '2'),           -- after-hours: hours of slack around observed min/max
    ('max_travel_speed_kmh',      '900');         -- impossible travel: max plausible speed (commercial cruise ~900 km/h)

-- ============================================================================
-- EMPLOYEE DATA (22 accounts: 20 employees + 2 service accounts)
-- ============================================================================

INSERT INTO employees VALUES
-- Active employees
('E001', 'Alice', 'Chen', 'Finance', 'New York', 'Active', '2019-03-15'),
('E002', 'Bob', 'Martinez', 'Engineering', 'San Francisco', 'Active', '2020-06-01'),
('E003', 'Carol', 'Johnson', 'IT Security', 'Austin', 'Active', '2018-11-20'),
('E004', 'David', 'Kim', 'Sales', 'Chicago', 'Active', '2021-02-10'),
('E005', 'Eva', 'Patel', 'HR', 'New York', 'Active', '2019-08-05'),
('E006', 'Frank', 'Williams', 'Engineering', 'San Francisco', 'Active', '2020-01-15'),
('E007', 'Grace', 'Lee', 'Finance', 'New York', 'Active', '2017-05-22'),
('E008', 'Henry', 'Brown', 'IT Infrastructure', 'Austin', 'Active', '2016-09-01'),
('E009', 'Iris', 'Davis', 'Marketing', 'Chicago', 'Active', '2022-03-01'),
('E010', 'Jack', 'Wilson', 'Engineering', 'San Francisco', 'Active', '2021-07-15'),
('E011', 'Karen', 'Taylor', 'Legal', 'New York', 'Active', '2018-04-10'),
('E012', 'Leo', 'Anderson', 'Sales', 'Chicago', 'Active', '2020-11-30'),
('E013', 'Maria', 'Garcia', 'Engineering', 'San Francisco', 'Active', '2019-01-08'),
('E014', 'Nathan', 'Thomas', 'Finance', 'New York', 'Active', '2022-06-15'),
('E015', 'Olivia', 'Moore', 'IT Security', 'Austin', 'Active', '2017-12-01'),
-- Terminated employee (for inactive account testing)
('E016', 'Peter', 'Jackson', 'Sales', 'Chicago', 'Terminated', '2019-05-01'),
-- Service accounts
('svc_backup', 'Service', 'Backup', 'IT Infrastructure', 'DataCenter', 'Active', '2015-01-01'),
('svc_monitor', 'Service', 'Monitor', 'IT Infrastructure', 'DataCenter', 'Active', '2015-01-01'),
-- More active employees. E017 has no logins before the detection window —
-- a dormant account (extended leave) that exercises the no-baseline branch
-- of the unfamiliar-country rule as a BENIGN case.
('E017', 'Quinn', 'Harris', 'Engineering', 'San Francisco', 'Active', '2021-09-01'),
('E018', 'Rachel', 'Clark', 'Marketing', 'Chicago', 'Active', '2020-04-15'),
('E019', 'Sam', 'Lewis', 'HR', 'New York', 'Active', '2019-07-22'),
('E020', 'Tina', 'Walker', 'Legal', 'New York', 'Active', '2018-10-05');

-- ============================================================================
-- MACHINE INVENTORY (Primary)
-- ============================================================================

INSERT INTO machines VALUES
-- Well-patched machines
('DEV-001', 'E001', 'Windows 11 Pro', '2025-01-15', 'Laptop'),
('DEV-002', 'E002', 'macOS 14.2', '2025-01-10', 'Laptop'),
('DEV-003', 'E003', 'Windows 11 Pro', '2025-01-18', 'Workstation'),
('DEV-004', 'E004', 'Windows 11 Pro', '2025-01-12', 'Laptop'),
('DEV-005', 'E005', 'Windows 11 Pro', '2025-01-14', 'Laptop'),
('DEV-006', 'E006', 'Ubuntu 22.04', '2025-01-16', 'Workstation'),
('DEV-007', 'E007', 'Windows 11 Pro', '2025-01-08', 'Laptop'),
-- Moderately outdated (60-90 days)
('DEV-008', 'E008', 'Windows Server 2022', '2024-11-01', 'Server'),
('DEV-009', 'E009', 'macOS 14.1', '2024-10-25', 'Laptop'),
('DEV-010', 'E010', 'Ubuntu 22.04', '2024-11-15', 'Workstation'),
-- SEVERELY OUTDATED (anomaly): 245 and 219 days at asof_date 2025-01-20
('DEV-011', 'E011', 'Windows 10', '2024-05-20', 'Laptop'),
('DEV-012', 'E012', 'Windows 10', '2024-06-15', 'Laptop'),
-- More current machines
('DEV-013', 'E013', 'macOS 14.2', '2025-01-17', 'Laptop'),
('DEV-014', 'E014', 'Windows 11 Pro', '2025-01-19', 'Laptop'),
('DEV-015', 'E015', 'Windows 11 Pro', '2025-01-11', 'Workstation'),
-- Server infrastructure. SRV-001 is CRITICAL: 285 days since patch at asof_date.
('SRV-001', 'svc_backup', 'Windows Server 2019', '2024-04-10', 'Server'),
('SRV-002', 'svc_monitor', 'Ubuntu 20.04', '2025-01-05', 'Server'),
-- Orphan device (no valid owner) - for integrity testing
('DEV-099', 'E999', 'Windows 10', '2024-08-01', 'Laptop');

-- ============================================================================
-- MACHINE INVENTORY (Backup - with intentional discrepancies)
-- ============================================================================

INSERT INTO machines_backup VALUES
('DEV-001', 'E001'),
('DEV-002', 'E002'),
('DEV-003', 'E003'),
('DEV-004', 'E004'),
('DEV-005', 'E005'),
('DEV-006', 'E006'),
('DEV-007', 'E007'),
('DEV-008', 'E008'),
('DEV-009', 'E009'),
('DEV-010', 'E010'),
-- MISMATCH: DEV-011 shows different owner in backup
('DEV-011', 'E007'),  -- Primary says E011, backup says E007
('DEV-012', 'E012'),
('DEV-013', 'E013'),
('DEV-014', 'E014'),
('DEV-015', 'E015'),
('SRV-001', 'svc_backup'),
('SRV-002', 'svc_monitor');

-- ============================================================================
-- LOGIN DATA (161 events, explicit event_ids)
-- Baseline period: 2025-01-06 .. 2025-01-10 (login_date < baseline_end)
-- Detection period: 2025-01-13 onward
-- ============================================================================

-- Alice Chen (E001) - Finance, NY - Normal pattern: US logins, hours 13-14 UTC
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(1,  'E001', '2025-01-06', '13:15:00', 'US', 1, '10.1.1.101'),
(2,  'E001', '2025-01-07', '13:22:00', 'US', 1, '10.1.1.101'),
(3,  'E001', '2025-01-08', '13:45:00', 'US', 1, '10.1.1.101'),
(4,  'E001', '2025-01-09', '14:01:00', 'US', 1, '10.1.1.101'),
(5,  'E001', '2025-01-10', '13:30:00', 'US', 1, '10.1.1.101'),
(6,  'E001', '2025-01-13', '13:18:00', 'US', 1, '10.1.1.101'),
(7,  'E001', '2025-01-14', '13:25:00', 'US', 1, '10.1.1.101'),
(8,  'E001', '2025-01-15', '14:10:00', 'US', 1, '10.1.1.101'),
-- ANOMALY: login from China at 03:27 UTC (unfamiliar country + odd hour).
-- The return to US 10.8h later (event 10) requires ~1,040 km/h — over the
-- 900 km/h gate. The OUTBOUND leg (event 8 -> 9, 13.3h, ~845 km/h) is under
-- the gate: borderline-possible by velocity alone, suspicious in combination.
(9,  'E001', '2025-01-16', '03:27:00', 'CN', 1, '203.45.67.89'),
(10, 'E001', '2025-01-16', '14:15:00', 'US', 1, '10.1.1.101'),
(11, 'E001', '2025-01-17', '13:40:00', 'US', 1, '10.1.1.101');

-- Bob Martinez (E002) - Engineering, SF - Normal: US, occasional CA (travels)
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(12, 'E002', '2025-01-06', '17:00:00', 'US', 1, '10.2.1.102'),
(13, 'E002', '2025-01-07', '16:45:00', 'US', 1, '10.2.1.102'),
(14, 'E002', '2025-01-08', '17:30:00', 'CA', 1, '24.150.22.33'),  -- Canada trip
(15, 'E002', '2025-01-09', '17:15:00', 'CA', 1, '24.150.22.33'),
(16, 'E002', '2025-01-10', '16:50:00', 'US', 1, '10.2.1.102'),
(17, 'E002', '2025-01-13', '17:05:00', 'US', 1, '10.2.1.102'),
(18, 'E002', '2025-01-14', '17:20:00', 'US', 1, '10.2.1.102'),
(19, 'E002', '2025-01-15', '16:55:00', 'US', 1, '10.2.1.102'),
-- BENIGN by design: US -> CA 5.5h apart (~345 km/h required velocity).
-- The old country!=country + 0-12h rule would flag this pair; the
-- velocity-gated rule correctly does not. Documented tuning demonstrator.
(20, 'E002', '2025-01-17', '14:00:00', 'US', 1, '10.2.1.102'),
(21, 'E002', '2025-01-17', '19:30:00', 'CA', 1, '24.150.22.33');

-- Carol Johnson (E003) - IT Security, Austin - Admin account, strict pattern
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(22, 'E003', '2025-01-06', '14:00:00', 'US', 1, '10.3.1.103'),
(23, 'E003', '2025-01-07', '14:15:00', 'US', 1, '10.3.1.103'),
(24, 'E003', '2025-01-08', '13:50:00', 'US', 1, '10.3.1.103'),
(25, 'E003', '2025-01-09', '14:30:00', 'US', 1, '10.3.1.103'),
(26, 'E003', '2025-01-10', '14:05:00', 'US', 1, '10.3.1.103'),
(27, 'E003', '2025-01-13', '14:10:00', 'US', 1, '10.3.1.103'),
(28, 'E003', '2025-01-14', '13:55:00', 'US', 1, '10.3.1.103'),
(29, 'E003', '2025-01-15', '14:20:00', 'US', 1, '10.3.1.103');

-- David Kim (E004) - Sales, Chicago - BRUTE FORCE TARGET
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(30, 'E004', '2025-01-06', '14:30:00', 'US', 1, '10.4.1.104'),
(31, 'E004', '2025-01-07', '14:45:00', 'US', 1, '10.4.1.104'),
(32, 'E004', '2025-01-08', '15:00:00', 'US', 1, '10.4.1.104'),
(33, 'E004', '2025-01-09', '14:20:00', 'US', 1, '10.4.1.104'),
(34, 'E004', '2025-01-10', '14:35:00', 'US', 1, '10.4.1.104'),
-- ANOMALY (campaign bf-e004): 8 uninterrupted failures then success within
-- 10 minutes, all from 185.220.101.45 (known Tor exit range 185.220.101.0/24).
(35, 'E004', '2025-01-15', '10:01:00', 'US', 0, '185.220.101.45'),
(36, 'E004', '2025-01-15', '10:02:15', 'US', 0, '185.220.101.45'),
(37, 'E004', '2025-01-15', '10:03:22', 'US', 0, '185.220.101.45'),
(38, 'E004', '2025-01-15', '10:04:45', 'US', 0, '185.220.101.45'),
(39, 'E004', '2025-01-15', '10:05:58', 'US', 0, '185.220.101.45'),
(40, 'E004', '2025-01-15', '10:07:10', 'US', 0, '185.220.101.45'),
(41, 'E004', '2025-01-15', '10:08:33', 'US', 0, '185.220.101.45'),
(42, 'E004', '2025-01-15', '10:09:41', 'US', 0, '185.220.101.45'),
(43, 'E004', '2025-01-15', '10:10:55', 'US', 1, '185.220.101.45'),  -- SUCCESS after failures
(44, 'E004', '2025-01-16', '14:40:00', 'US', 1, '10.4.1.104');

-- Grace Lee (E007) - Finance, NY - IMPOSSIBLE TRAVEL
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(45, 'E007', '2025-01-06', '14:00:00', 'US', 1, '10.1.1.107'),
(46, 'E007', '2025-01-07', '13:45:00', 'US', 1, '10.1.1.107'),
(47, 'E007', '2025-01-08', '14:10:00', 'US', 1, '10.1.1.107'),
(48, 'E007', '2025-01-09', '13:55:00', 'US', 1, '10.1.1.107'),
(49, 'E007', '2025-01-10', '14:05:00', 'US', 1, '10.1.1.107'),
-- ANOMALY: Germany then US 4.25h later (~1,835 km/h required velocity)
(50, 'E007', '2025-01-14', '08:30:00', 'DE', 1, '91.216.45.123'),  -- Germany
(51, 'E007', '2025-01-14', '12:45:00', 'US', 1, '10.1.1.107'),     -- US 4.25 hours later
(52, 'E007', '2025-01-15', '14:00:00', 'US', 1, '10.1.1.107'),
(53, 'E007', '2025-01-16', '13:50:00', 'US', 1, '10.1.1.107');

-- Henry Brown (E008) - IT Infrastructure - Normal admin patterns
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(54, 'E008', '2025-01-06', '15:00:00', 'US', 1, '10.5.1.108'),
(55, 'E008', '2025-01-07', '15:15:00', 'US', 1, '10.5.1.108'),
(56, 'E008', '2025-01-08', '14:45:00', 'US', 1, '10.5.1.108'),
(57, 'E008', '2025-01-09', '15:30:00', 'US', 1, '10.5.1.108'),
(58, 'E008', '2025-01-10', '15:05:00', 'US', 1, '10.5.1.108'),
(59, 'E008', '2025-01-13', '15:10:00', 'US', 1, '10.5.1.108'),
(60, 'E008', '2025-01-14', '14:55:00', 'US', 1, '10.5.1.108'),
(61, 'E008', '2025-01-15', '15:20:00', 'US', 1, '10.5.1.108');

-- Karen Taylor (E011) - Legal, NY - AFTER HOURS ANOMALY
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(62, 'E011', '2025-01-06', '14:30:00', 'US', 1, '10.1.1.111'),
(63, 'E011', '2025-01-07', '14:15:00', 'US', 1, '10.1.1.111'),
(64, 'E011', '2025-01-08', '14:45:00', 'US', 1, '10.1.1.111'),
(65, 'E011', '2025-01-09', '14:20:00', 'US', 1, '10.1.1.111'),
(66, 'E011', '2025-01-10', '14:35:00', 'US', 1, '10.1.1.111'),
-- ANOMALY: 02:30 UTC login from a residential-looking IP. E011's observed
-- baseline hours are 14-14 -> personal window [12,16] with +/-2 tolerance.
(67, 'E011', '2025-01-15', '02:30:00', 'US', 1, '73.45.123.88'),
(68, 'E011', '2025-01-15', '14:25:00', 'US', 1, '10.1.1.111'),
(69, 'E011', '2025-01-16', '14:40:00', 'US', 1, '10.1.1.111');

-- Leo Anderson (E012) - Sales, Chicago - FAILED BRUTE FORCE TARGET
-- (25 failures against ONE account from ONE IP is brute force that never
-- succeeded, NOT a password spray. Spray = one source, MANY accounts, few
-- attempts each — see campaign spray-20250116 below.)
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(70, 'E012', '2025-01-06', '15:00:00', 'US', 1, '10.4.1.112'),
(71, 'E012', '2025-01-07', '15:30:00', 'US', 1, '10.4.1.112'),
(72, 'E012', '2025-01-08', '15:15:00', 'US', 1, '10.4.1.112'),
-- ANOMALY (campaign bf-e012): 25 failed logins in 6 minutes, no success
(73, 'E012', '2025-01-13', '04:01:00', 'US', 0, '45.33.32.156'),
(74, 'E012', '2025-01-13', '04:01:15', 'US', 0, '45.33.32.156'),
(75, 'E012', '2025-01-13', '04:01:30', 'US', 0, '45.33.32.156'),
(76, 'E012', '2025-01-13', '04:01:45', 'US', 0, '45.33.32.156'),
(77, 'E012', '2025-01-13', '04:02:00', 'US', 0, '45.33.32.156'),
(78, 'E012', '2025-01-13', '04:02:15', 'US', 0, '45.33.32.156'),
(79, 'E012', '2025-01-13', '04:02:30', 'US', 0, '45.33.32.156'),
(80, 'E012', '2025-01-13', '04:02:45', 'US', 0, '45.33.32.156'),
(81, 'E012', '2025-01-13', '04:03:00', 'US', 0, '45.33.32.156'),
(82, 'E012', '2025-01-13', '04:03:15', 'US', 0, '45.33.32.156'),
(83, 'E012', '2025-01-13', '04:03:30', 'US', 0, '45.33.32.156'),
(84, 'E012', '2025-01-13', '04:03:45', 'US', 0, '45.33.32.156'),
(85, 'E012', '2025-01-13', '04:04:00', 'US', 0, '45.33.32.156'),
(86, 'E012', '2025-01-13', '04:04:15', 'US', 0, '45.33.32.156'),
(87, 'E012', '2025-01-13', '04:04:30', 'US', 0, '45.33.32.156'),
(88, 'E012', '2025-01-13', '04:04:45', 'US', 0, '45.33.32.156'),
(89, 'E012', '2025-01-13', '04:05:00', 'US', 0, '45.33.32.156'),
(90, 'E012', '2025-01-13', '04:05:15', 'US', 0, '45.33.32.156'),
(91, 'E012', '2025-01-13', '04:05:30', 'US', 0, '45.33.32.156'),
(92, 'E012', '2025-01-13', '04:05:45', 'US', 0, '45.33.32.156'),
(93, 'E012', '2025-01-13', '04:06:00', 'US', 0, '45.33.32.156'),
(94, 'E012', '2025-01-13', '04:06:15', 'US', 0, '45.33.32.156'),
(95, 'E012', '2025-01-13', '04:06:30', 'US', 0, '45.33.32.156'),
(96, 'E012', '2025-01-13', '04:06:45', 'US', 0, '45.33.32.156'),
(97, 'E012', '2025-01-13', '04:07:00', 'US', 0, '45.33.32.156'),
-- Back to normal
(98, 'E012', '2025-01-14', '15:20:00', 'US', 1, '10.4.1.112'),
(99, 'E012', '2025-01-15', '15:05:00', 'US', 1, '10.4.1.112');

-- TERMINATED EMPLOYEE (E016) - Should not have ANY logins
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(100, 'E016', '2025-01-14', '22:15:00', 'US', 0, '104.28.55.77'),  -- Failed attempt
(101, 'E016', '2025-01-14', '22:16:00', 'US', 0, '104.28.55.77'),  -- Another failed
(102, 'E016', '2025-01-15', '01:30:00', 'RU', 1, '95.213.45.67');  -- SUCCESS from Russia!

-- Service accounts - baseline normal behavior
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(103, 'svc_backup', '2025-01-06', '02:00:00', 'US', 1, '10.0.0.50'),
(104, 'svc_backup', '2025-01-07', '02:00:00', 'US', 1, '10.0.0.50'),
(105, 'svc_backup', '2025-01-08', '02:00:00', 'US', 1, '10.0.0.50'),
(106, 'svc_backup', '2025-01-09', '02:00:00', 'US', 1, '10.0.0.50'),
(107, 'svc_backup', '2025-01-10', '02:00:00', 'US', 1, '10.0.0.50'),
(108, 'svc_backup', '2025-01-13', '02:00:00', 'US', 1, '10.0.0.50'),
(109, 'svc_backup', '2025-01-14', '02:00:00', 'US', 1, '10.0.0.50'),
(110, 'svc_backup', '2025-01-15', '02:00:00', 'US', 1, '10.0.0.50'),
(111, 'svc_monitor', '2025-01-06', '00:00:00', 'US', 1, '10.0.0.51'),
(112, 'svc_monitor', '2025-01-07', '00:00:00', 'US', 1, '10.0.0.51'),
(113, 'svc_monitor', '2025-01-08', '00:00:00', 'US', 1, '10.0.0.51'),
(114, 'svc_monitor', '2025-01-09', '00:00:00', 'US', 1, '10.0.0.51'),
(115, 'svc_monitor', '2025-01-10', '00:00:00', 'US', 1, '10.0.0.51'),
(116, 'svc_monitor', '2025-01-13', '00:00:00', 'US', 1, '10.0.0.51'),
(117, 'svc_monitor', '2025-01-14', '00:00:00', 'US', 1, '10.0.0.51'),
(118, 'svc_monitor', '2025-01-15', '00:00:00', 'US', 1, '10.0.0.51');

-- Additional baseline logins for other employees (normal behavior)
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(119, 'E005', '2025-01-06', '14:00:00', 'US', 1, '10.1.1.105'),
(120, 'E005', '2025-01-07', '14:15:00', 'US', 1, '10.1.1.105'),
(121, 'E005', '2025-01-08', '13:50:00', 'US', 1, '10.1.1.105'),
(122, 'E006', '2025-01-06', '17:30:00', 'US', 1, '10.2.1.106'),
(123, 'E006', '2025-01-07', '17:45:00', 'US', 1, '10.2.1.106'),
(124, 'E006', '2025-01-08', '17:15:00', 'US', 1, '10.2.1.106'),
(125, 'E009', '2025-01-06', '15:00:00', 'US', 1, '10.4.1.109'),
(126, 'E009', '2025-01-07', '15:30:00', 'US', 1, '10.4.1.109'),
(127, 'E010', '2025-01-06', '17:00:00', 'US', 1, '10.2.1.110'),
(128, 'E010', '2025-01-07', '17:20:00', 'US', 1, '10.2.1.110'),
(129, 'E013', '2025-01-06', '17:15:00', 'US', 1, '10.2.1.113'),
(130, 'E013', '2025-01-07', '17:30:00', 'US', 1, '10.2.1.113'),
(131, 'E014', '2025-01-06', '14:10:00', 'US', 1, '10.1.1.114'),
(132, 'E014', '2025-01-07', '14:25:00', 'US', 1, '10.1.1.114'),
(133, 'E015', '2025-01-06', '14:45:00', 'US', 1, '10.3.1.115'),
(134, 'E015', '2025-01-07', '15:00:00', 'US', 1, '10.3.1.115');

-- Quinn Harris (E017) - Engineering, SF - BENIGN NO-BASELINE ACCOUNT
-- Returns from extended leave: first observed logins fall inside the
-- detection window, so the unfamiliar-country rule has no baseline for the
-- account. This is the deliberate benign false positive that keeps Rule 1's
-- measured precision honest (0.75, not a suspicious 1.00).
-- Times sit inside Engineering's department hour window [14,19].
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(135, 'E017', '2025-01-16', '15:30:00', 'US', 1, '10.2.1.117'),
(136, 'E017', '2025-01-17', '15:45:00', 'US', 1, '10.2.1.117');

-- PASSWORD SPRAY CAMPAIGN (campaign spray-20250116)
-- One external source (45.33.32.201 — inside the 45.33.32.0/24 scanner range,
-- same range as the bf-e012 source) walks 10 accounts with 2-3 attempts each:
-- low-and-slow per account, loud across accounts. No successes.
-- Per-account counts stay below both brute-force thresholds by design.
INSERT INTO log_in_attempts (event_id, username, login_date, login_time, country, success, source_ip) VALUES
(137, 'E002', '2025-01-16', '05:00:10', 'US', 0, '45.33.32.201'),
(138, 'E002', '2025-01-16', '05:01:40', 'US', 0, '45.33.32.201'),
(139, 'E002', '2025-01-16', '05:03:10', 'US', 0, '45.33.32.201'),
(140, 'E003', '2025-01-16', '05:04:40', 'US', 0, '45.33.32.201'),
(141, 'E003', '2025-01-16', '05:06:10', 'US', 0, '45.33.32.201'),
(142, 'E005', '2025-01-16', '05:07:40', 'US', 0, '45.33.32.201'),
(143, 'E005', '2025-01-16', '05:09:10', 'US', 0, '45.33.32.201'),
(144, 'E005', '2025-01-16', '05:10:40', 'US', 0, '45.33.32.201'),
(145, 'E006', '2025-01-16', '05:12:10', 'US', 0, '45.33.32.201'),
(146, 'E006', '2025-01-16', '05:13:40', 'US', 0, '45.33.32.201'),
(147, 'E008', '2025-01-16', '05:15:10', 'US', 0, '45.33.32.201'),
(148, 'E008', '2025-01-16', '05:16:40', 'US', 0, '45.33.32.201'),
(149, 'E008', '2025-01-16', '05:18:10', 'US', 0, '45.33.32.201'),
(150, 'E009', '2025-01-16', '05:19:40', 'US', 0, '45.33.32.201'),
(151, 'E009', '2025-01-16', '05:21:10', 'US', 0, '45.33.32.201'),
(152, 'E010', '2025-01-16', '05:22:40', 'US', 0, '45.33.32.201'),
(153, 'E010', '2025-01-16', '05:24:10', 'US', 0, '45.33.32.201'),
(154, 'E010', '2025-01-16', '05:25:40', 'US', 0, '45.33.32.201'),
(155, 'E013', '2025-01-16', '05:27:10', 'US', 0, '45.33.32.201'),
(156, 'E013', '2025-01-16', '05:28:40', 'US', 0, '45.33.32.201'),
(157, 'E014', '2025-01-16', '05:30:10', 'US', 0, '45.33.32.201'),
(158, 'E014', '2025-01-16', '05:31:40', 'US', 0, '45.33.32.201'),
(159, 'E014', '2025-01-16', '05:33:10', 'US', 0, '45.33.32.201'),
(160, 'E015', '2025-01-16', '05:34:40', 'US', 0, '45.33.32.201'),
(161, 'E015', '2025-01-16', '05:36:10', 'US', 0, '45.33.32.201');

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX idx_login_username ON log_in_attempts(username);
CREATE INDEX idx_login_date ON log_in_attempts(login_date);
CREATE INDEX idx_login_success ON log_in_attempts(success);
CREATE INDEX idx_login_country ON log_in_attempts(country);
CREATE INDEX idx_machines_employee ON machines(employee_id);

-- ============================================================================
-- SUMMARY: EMBEDDED ANOMALIES (ground truth lives in data/ground_truth.sql)
-- ============================================================================
-- 1. E001 (Alice Chen): CN login at 03:27 UTC (event 9) + CN->US return at
--    ~1,040 km/h required velocity (event 10)
-- 2. E004 (David Kim): brute force — 8 failures then success in 10 min from
--    Tor exit range IP (events 35-43, campaign bf-e004)
-- 3. E007 (Grace Lee): DE login (event 50) + DE->US in 4.25h, ~1,835 km/h
--    (event 51)
-- 4. E011 (Karen Taylor): 02:30 UTC login vs personal 14:00-15:00 baseline
--    (event 67)
-- 5. E012 (Leo Anderson): FAILED brute force — 25 failures, one account, one
--    IP, no success (events 73-97, campaign bf-e012)
-- 6. E016 (Peter Jackson): terminated account, 2 failures + RU success
--    (events 100-102)
-- 7. spray-20250116: password spray — one IP (45.33.32.201), 10 accounts,
--    2-3 failures each, no success (events 137-161)
-- 8. DEV-011: inventory mismatch (primary owner E011 vs backup owner E007)
-- 9. DEV-099: orphan device (owner E999 does not exist)
-- 10. SRV-001: critically outdated server (285 days since patch at asof_date)
-- BENIGN by design: E002 US->CA pair (events 20-21, velocity tuning
-- demonstrator); E017 no-baseline first logins (events 135-136)
-- ============================================================================
