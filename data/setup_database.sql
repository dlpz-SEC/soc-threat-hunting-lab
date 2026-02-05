-- ============================================================================
-- SOC THREAT HUNTING LAB: SYNTHETIC DATASET
-- Purpose: Realistic enterprise security telemetry with embedded anomalies
-- Database: SQLite (portable) or MariaDB compatible
-- ============================================================================

-- Clean slate
DROP TABLE IF EXISTS log_in_attempts;
DROP TABLE IF EXISTS machines;
DROP TABLE IF EXISTS machines_backup;
DROP TABLE IF EXISTS employees;

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
-- EMPLOYEE DATA (30 employees across departments)
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
-- More active employees
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
-- SEVERELY OUTDATED (anomaly)
('DEV-011', 'E011', 'Windows 10', '2024-05-20', 'Laptop'),  -- 240+ days
('DEV-012', 'E012', 'Windows 10', '2024-06-15', 'Laptop'),  -- 210+ days
-- More current machines
('DEV-013', 'E013', 'macOS 14.2', '2025-01-17', 'Laptop'),
('DEV-014', 'E014', 'Windows 11 Pro', '2025-01-19', 'Laptop'),
('DEV-015', 'E015', 'Windows 11 Pro', '2025-01-11', 'Workstation'),
-- Server infrastructure
('SRV-001', 'svc_backup', 'Windows Server 2019', '2024-04-10', 'Server'),  -- CRITICAL: Very outdated
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
-- LOGIN DATA: BASELINE NORMAL BEHAVIOR (2 weeks of data)
-- ============================================================================

-- Alice Chen (E001) - Finance, NY - Normal pattern: US logins, 8am-6pm ET
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E001', '2025-01-06', '13:15:00', 'US', 1, '10.1.1.101'),
('E001', '2025-01-07', '13:22:00', 'US', 1, '10.1.1.101'),
('E001', '2025-01-08', '13:45:00', 'US', 1, '10.1.1.101'),
('E001', '2025-01-09', '14:01:00', 'US', 1, '10.1.1.101'),
('E001', '2025-01-10', '13:30:00', 'US', 1, '10.1.1.101'),
('E001', '2025-01-13', '13:18:00', 'US', 1, '10.1.1.101'),
('E001', '2025-01-14', '13:25:00', 'US', 1, '10.1.1.101'),
('E001', '2025-01-15', '14:10:00', 'US', 1, '10.1.1.101'),
-- ANOMALY: Alice logs in from China at 3am UTC (unexpected location + time)
('E001', '2025-01-16', '03:27:00', 'CN', 1, '203.45.67.89'),
('E001', '2025-01-16', '14:15:00', 'US', 1, '10.1.1.101'),  -- Back to normal same day
('E001', '2025-01-17', '13:40:00', 'US', 1, '10.1.1.101');

-- Bob Martinez (E002) - Engineering, SF - Normal: US, occasional CA (travels)
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E002', '2025-01-06', '17:00:00', 'US', 1, '10.2.1.102'),
('E002', '2025-01-07', '16:45:00', 'US', 1, '10.2.1.102'),
('E002', '2025-01-08', '17:30:00', 'CA', 1, '24.150.22.33'),  -- Canada trip
('E002', '2025-01-09', '17:15:00', 'CA', 1, '24.150.22.33'),
('E002', '2025-01-10', '16:50:00', 'US', 1, '10.2.1.102'),
('E002', '2025-01-13', '17:05:00', 'US', 1, '10.2.1.102'),
('E002', '2025-01-14', '17:20:00', 'US', 1, '10.2.1.102'),
('E002', '2025-01-15', '16:55:00', 'US', 1, '10.2.1.102');

-- Carol Johnson (E003) - IT Security, Austin - Admin account, strict pattern
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E003', '2025-01-06', '14:00:00', 'US', 1, '10.3.1.103'),
('E003', '2025-01-07', '14:15:00', 'US', 1, '10.3.1.103'),
('E003', '2025-01-08', '13:50:00', 'US', 1, '10.3.1.103'),
('E003', '2025-01-09', '14:30:00', 'US', 1, '10.3.1.103'),
('E003', '2025-01-10', '14:05:00', 'US', 1, '10.3.1.103'),
('E003', '2025-01-13', '14:10:00', 'US', 1, '10.3.1.103'),
('E003', '2025-01-14', '13:55:00', 'US', 1, '10.3.1.103'),
('E003', '2025-01-15', '14:20:00', 'US', 1, '10.3.1.103');

-- David Kim (E004) - Sales, Chicago - BRUTE FORCE TARGET
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E004', '2025-01-06', '14:30:00', 'US', 1, '10.4.1.104'),
('E004', '2025-01-07', '14:45:00', 'US', 1, '10.4.1.104'),
('E004', '2025-01-08', '15:00:00', 'US', 1, '10.4.1.104'),
('E004', '2025-01-09', '14:20:00', 'US', 1, '10.4.1.104'),
('E004', '2025-01-10', '14:35:00', 'US', 1, '10.4.1.104'),
-- ANOMALY: Brute force attack - 8 failures then success
('E004', '2025-01-15', '10:01:00', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:02:15', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:03:22', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:04:45', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:05:58', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:07:10', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:08:33', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:09:41', 'US', 0, '185.220.101.45'),
('E004', '2025-01-15', '10:10:55', 'US', 1, '185.220.101.45'),  -- SUCCESS after failures
('E004', '2025-01-16', '14:40:00', 'US', 1, '10.4.1.104');

-- Grace Lee (E007) - Finance, NY - IMPOSSIBLE TRAVEL
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E007', '2025-01-06', '14:00:00', 'US', 1, '10.1.1.107'),
('E007', '2025-01-07', '13:45:00', 'US', 1, '10.1.1.107'),
('E007', '2025-01-08', '14:10:00', 'US', 1, '10.1.1.107'),
('E007', '2025-01-09', '13:55:00', 'US', 1, '10.1.1.107'),
('E007', '2025-01-10', '14:05:00', 'US', 1, '10.1.1.107'),
-- ANOMALY: Impossible travel - Germany then US 4 hours later
('E007', '2025-01-14', '08:30:00', 'DE', 1, '91.216.45.123'),  -- Germany
('E007', '2025-01-14', '12:45:00', 'US', 1, '10.1.1.107'),     -- US 4 hours later (impossible)
('E007', '2025-01-15', '14:00:00', 'US', 1, '10.1.1.107'),
('E007', '2025-01-16', '13:50:00', 'US', 1, '10.1.1.107');

-- Henry Brown (E008) - IT Infrastructure - Normal admin patterns
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E008', '2025-01-06', '15:00:00', 'US', 1, '10.5.1.108'),
('E008', '2025-01-07', '15:15:00', 'US', 1, '10.5.1.108'),
('E008', '2025-01-08', '14:45:00', 'US', 1, '10.5.1.108'),
('E008', '2025-01-09', '15:30:00', 'US', 1, '10.5.1.108'),
('E008', '2025-01-10', '15:05:00', 'US', 1, '10.5.1.108'),
('E008', '2025-01-13', '15:10:00', 'US', 1, '10.5.1.108'),
('E008', '2025-01-14', '14:55:00', 'US', 1, '10.5.1.108'),
('E008', '2025-01-15', '15:20:00', 'US', 1, '10.5.1.108');

-- Karen Taylor (E011) - Legal, NY - AFTER HOURS ANOMALY
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E011', '2025-01-06', '14:30:00', 'US', 1, '10.1.1.111'),
('E011', '2025-01-07', '14:15:00', 'US', 1, '10.1.1.111'),
('E011', '2025-01-08', '14:45:00', 'US', 1, '10.1.1.111'),
('E011', '2025-01-09', '14:20:00', 'US', 1, '10.1.1.111'),
('E011', '2025-01-10', '14:35:00', 'US', 1, '10.1.1.111'),
-- ANOMALY: 2:30 AM login (very unusual for non-IT employee)
('E011', '2025-01-15', '02:30:00', 'US', 1, '73.45.123.88'),
('E011', '2025-01-15', '14:25:00', 'US', 1, '10.1.1.111'),
('E011', '2025-01-16', '14:40:00', 'US', 1, '10.1.1.111');

-- Leo Anderson (E012) - Sales, Chicago - PASSWORD SPRAY TARGET
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E012', '2025-01-06', '15:00:00', 'US', 1, '10.4.1.112'),
('E012', '2025-01-07', '15:30:00', 'US', 1, '10.4.1.112'),
('E012', '2025-01-08', '15:15:00', 'US', 1, '10.4.1.112'),
-- ANOMALY: 25 failed logins (password spraying attack)
('E012', '2025-01-13', '04:01:00', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:01:15', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:01:30', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:01:45', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:02:00', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:02:15', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:02:30', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:02:45', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:03:00', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:03:15', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:03:30', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:03:45', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:04:00', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:04:15', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:04:30', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:04:45', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:05:00', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:05:15', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:05:30', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:05:45', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:06:00', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:06:15', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:06:30', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:06:45', 'US', 0, '45.33.32.156'),
('E012', '2025-01-13', '04:07:00', 'US', 0, '45.33.32.156'),
-- Back to normal
('E012', '2025-01-14', '15:20:00', 'US', 1, '10.4.1.112'),
('E012', '2025-01-15', '15:05:00', 'US', 1, '10.4.1.112');

-- TERMINATED EMPLOYEE - Should not have ANY logins
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
-- ANOMALY: Terminated user account activity
('E016', '2025-01-14', '22:15:00', 'US', 0, '104.28.55.77'),  -- Failed attempt
('E016', '2025-01-14', '22:16:00', 'US', 0, '104.28.55.77'),  -- Another failed
('E016', '2025-01-15', '01:30:00', 'RU', 1, '95.213.45.67');  -- SUCCESS from Russia!

-- Service accounts - baseline normal behavior
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('svc_backup', '2025-01-06', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_backup', '2025-01-07', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_backup', '2025-01-08', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_backup', '2025-01-09', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_backup', '2025-01-10', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_backup', '2025-01-13', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_backup', '2025-01-14', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_backup', '2025-01-15', '02:00:00', 'US', 1, '10.0.0.50'),
('svc_monitor', '2025-01-06', '00:00:00', 'US', 1, '10.0.0.51'),
('svc_monitor', '2025-01-07', '00:00:00', 'US', 1, '10.0.0.51'),
('svc_monitor', '2025-01-08', '00:00:00', 'US', 1, '10.0.0.51'),
('svc_monitor', '2025-01-09', '00:00:00', 'US', 1, '10.0.0.51'),
('svc_monitor', '2025-01-10', '00:00:00', 'US', 1, '10.0.0.51'),
('svc_monitor', '2025-01-13', '00:00:00', 'US', 1, '10.0.0.51'),
('svc_monitor', '2025-01-14', '00:00:00', 'US', 1, '10.0.0.51'),
('svc_monitor', '2025-01-15', '00:00:00', 'US', 1, '10.0.0.51');

-- Additional baseline logins for other employees (normal behavior)
INSERT INTO log_in_attempts (username, login_date, login_time, country, success, source_ip) VALUES
('E005', '2025-01-06', '14:00:00', 'US', 1, '10.1.1.105'),
('E005', '2025-01-07', '14:15:00', 'US', 1, '10.1.1.105'),
('E005', '2025-01-08', '13:50:00', 'US', 1, '10.1.1.105'),
('E006', '2025-01-06', '17:30:00', 'US', 1, '10.2.1.106'),
('E006', '2025-01-07', '17:45:00', 'US', 1, '10.2.1.106'),
('E006', '2025-01-08', '17:15:00', 'US', 1, '10.2.1.106'),
('E009', '2025-01-06', '15:00:00', 'US', 1, '10.4.1.109'),
('E009', '2025-01-07', '15:30:00', 'US', 1, '10.4.1.109'),
('E010', '2025-01-06', '17:00:00', 'US', 1, '10.2.1.110'),
('E010', '2025-01-07', '17:20:00', 'US', 1, '10.2.1.110'),
('E013', '2025-01-06', '17:15:00', 'US', 1, '10.2.1.113'),
('E013', '2025-01-07', '17:30:00', 'US', 1, '10.2.1.113'),
('E014', '2025-01-06', '14:10:00', 'US', 1, '10.1.1.114'),
('E014', '2025-01-07', '14:25:00', 'US', 1, '10.1.1.114'),
('E015', '2025-01-06', '14:45:00', 'US', 1, '10.3.1.115'),
('E015', '2025-01-07', '15:00:00', 'US', 1, '10.3.1.115');

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX idx_login_username ON log_in_attempts(username);
CREATE INDEX idx_login_date ON log_in_attempts(login_date);
CREATE INDEX idx_login_success ON log_in_attempts(success);
CREATE INDEX idx_login_country ON log_in_attempts(country);
CREATE INDEX idx_machines_employee ON machines(employee_id);

-- ============================================================================
-- SUMMARY: EMBEDDED ANOMALIES
-- ============================================================================
-- 1. E001 (Alice Chen): Unfamiliar country login from CN at 03:27 UTC
-- 2. E004 (David Kim): Brute force - 8 failures then success within 10 min
-- 3. E007 (Grace Lee): Impossible travel - DE to US in 4 hours
-- 4. E011 (Karen Taylor): After-hours login at 02:30 UTC
-- 5. E012 (Leo Anderson): Password spray - 25 failures in 6 minutes
-- 6. E016 (Peter Jackson): Terminated account with login attempts AND success from RU
-- 7. DEV-011: Inventory mismatch (different owner in primary vs backup)
-- 8. DEV-099: Orphan device (owner E999 doesn't exist)
-- 9. SRV-001: Critically outdated server (290+ days since patch)
-- ============================================================================
