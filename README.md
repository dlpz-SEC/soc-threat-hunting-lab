# SQL Threat Hunting Lab: Authentication Anomaly Investigation

<p align="center">
  <img src="https://img.shields.io/badge/Threat%20Hunting-SQL--Driven-2563EB?style=for-the-badge&logo=databricks&logoColor=white" />
  <img src="https://img.shields.io/badge/SOC-Investigation%20Workflow-F59E0B?style=for-the-badge&logo=elastic&logoColor=white" />
  <img src="https://img.shields.io/badge/Detection-Behavioral%20Logic-7C3AED?style=for-the-badge&logo=apachekafka&logoColor=white" />
  <img src="https://img.shields.io/badge/Triage-Risk%20Prioritization-DC2626?style=for-the-badge&logo=opsgenie&logoColor=white" />
  <img src="https://img.shields.io/badge/Data%20Integrity-Pre--Action%20Validated-16A34A?style=for-the-badge&logo=checkmarx&logoColor=white" />
  <img src="https://img.shields.io/badge/Execution-SOC--Ready%20Outputs-0A66C2?style=for-the-badge&logo=splunk&logoColor=white" />
</p>

**Portfolio Artifact** | Enterprise Security Analysis | January 2025

---

## Overview

This lab demonstrates a complete SOC investigation workflow using SQL-based threat hunting. Starting from raw authentication logs and asset inventory, I identify, triage, and prioritize security incidents for response.

**What this demonstrates:**
- Baseline establishment (distinguishing normal from anomalous)
- Detection engineering (writing rules that surface real threats)
- Investigation methodology (hypothesis → evidence → conclusion)
- Operational readiness (actionable outputs with confidence levels)

**Tools:** SQLite (portable; queries adapt to MySQL/MariaDB/MSSQL)  
**Data:** Synthetic enterprise telemetry with embedded anomalies (132 login events, 22 users, 18 devices)

---

## Phase 1: Baseline Enumeration

Before hunting anomalies, I establish what "normal" looks like.

### 1.1 Geographic Login Baseline

**Question:** Where do users typically log in from?

```sql
SELECT 
    username,
    GROUP_CONCAT(DISTINCT country) AS known_countries,
    COUNT(DISTINCT country) AS country_count
FROM log_in_attempts
WHERE success = 1
  AND login_date < '2025-01-13'  -- First week = baseline period
GROUP BY username;
```

**Results (sample):**

| username | known_countries | country_count |
|----------|-----------------|---------------|
| E001 | US | 1 |
| E002 | US,CA | 2 |
| E003 | US | 1 |
| E007 | US | 1 |

**Baseline finding:** Most users authenticate exclusively from the US. E002 shows US,CA pattern (legitimate cross-border travel documented). This becomes our geographic allowlist.

### 1.2 Endpoint Patch Posture

**Question:** Which devices represent elevated risk due to missing patches?

```sql
SELECT 
    m.device_id,
    e.first_name || ' ' || e.last_name AS owner_name,
    e.department,
    m.operating_system,
    CAST(julianday('2025-01-20') - julianday(m.os_patch_date) AS INTEGER) AS days_since_patch,
    CASE 
        WHEN julianday('2025-01-20') - julianday(m.os_patch_date) > 180 THEN 'CRITICAL'
        WHEN julianday('2025-01-20') - julianday(m.os_patch_date) > 90 THEN 'WARNING'
        ELSE 'OK'
    END AS patch_risk
FROM machines m
LEFT JOIN employees e ON m.employee_id = e.employee_id
ORDER BY days_since_patch DESC;
```

**Results (at-risk devices only):**

| device_id | owner_name | department | operating_system | days_since_patch | patch_risk |
|-----------|------------|------------|------------------|------------------|------------|
| SRV-001 | Service Backup | IT Infrastructure | Windows Server 2019 | 285 | CRITICAL |
| DEV-011 | Karen Taylor | Legal | Windows 10 | 245 | CRITICAL |
| DEV-012 | Leo Anderson | Sales | Windows 10 | 219 | CRITICAL |
| DEV-099 | (no owner) | | Windows 10 | 172 | WARNING |

**Baseline finding:** Three devices exceed 180-day patch threshold. SRV-001 is a backup server—compromise here enables data exfiltration or ransomware deployment. DEV-099 has no valid owner (integrity issue flagged for Phase 4).

---

## Phase 2: Anomaly Detection

With baselines established, I apply detection rules to surface deviations.

### Detection Rule 1: Unfamiliar Country Login

**Hypothesis:** Successful login from a country not in the user's baseline indicates potential credential theft.

```sql
SELECT 
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.country AS anomaly_country,
    b.known_countries AS baseline_countries,
    l.source_ip,
    'HIGH' AS severity
FROM log_in_attempts l
LEFT JOIN v_user_country_baseline b ON l.username = b.username
LEFT JOIN employees e ON l.username = e.employee_id
WHERE l.success = 1
  AND l.login_date >= '2025-01-13'
  AND (b.known_countries IS NULL 
       OR INSTR(',' || b.known_countries || ',', ',' || l.country || ',') = 0);
```

**Results:**

| username | user_name | department | timestamp | anomaly_country | baseline_countries |
|----------|-----------|------------|-----------|-----------------|-------------------|
| E001 | Alice Chen | Finance | 2025-01-16 03:27:00 | CN | US |
| E007 | Grace Lee | Finance | 2025-01-14 08:30:00 | DE | US |
| E016 | Peter Jackson | Sales | 2025-01-15 01:30:00 | RU | (none) |

**Analysis:**
- **E001:** Finance user with US-only baseline logged in from China at 03:27 UTC. Time aligns with business hours in China, not US—suspicious.
- **E007:** Finance user logged in from Germany. Requires correlation with travel records.
- **E016:** No baseline exists because this account had no prior successful logins in the detection period—this user is terminated (confirmed in employee table). A successful login from Russia on a terminated account is a **critical incident**.

### Detection Rule 2: Impossible Travel

**Hypothesis:** Same user appearing in geographically distant locations within impossible timeframes indicates credential sharing or compromise.

```sql
SELECT 
    a.username,
    e.first_name || ' ' || e.last_name AS user_name,
    a.login_date || ' ' || a.login_time AS timestamp_1,
    a.country AS country_1,
    b.login_date || ' ' || b.login_time AS timestamp_2,
    b.country AS country_2,
    ROUND((julianday(b.login_date || ' ' || b.login_time) - 
           julianday(a.login_date || ' ' || a.login_time)) * 24, 1) AS hours_apart
FROM log_in_attempts a
JOIN log_in_attempts b ON a.username = b.username
    AND a.event_id < b.event_id
    AND a.success = 1 AND b.success = 1
    AND a.country != b.country
LEFT JOIN employees e ON a.username = e.employee_id
WHERE (julianday(b.login_date || ' ' || b.login_time) - 
       julianday(a.login_date || ' ' || a.login_time)) * 24 BETWEEN 0 AND 12;
```

**Results:**

| username | user_name | timestamp_1 | country_1 | timestamp_2 | country_2 | hours_apart |
|----------|-----------|-------------|-----------|-------------|-----------|-------------|
| E001 | Alice Chen | 2025-01-16 03:27:00 | CN | 2025-01-16 14:15:00 | US | 10.8 |
| E007 | Grace Lee | 2025-01-14 08:30:00 | DE | 2025-01-14 12:45:00 | US | 4.3 |

**Analysis:**
- **E007:** Germany → US in 4.3 hours. Minimum flight time Frankfurt→NYC is ~8 hours. **Physically impossible.** Either (a) credential compromise with attacker in Germany, or (b) VPN misconfiguration. Either requires investigation.
- **E001:** China → US in 10.8 hours is borderline possible (some routes are ~13h), but combined with 03:27 login time (middle of night in US), this is highly suspicious.

### Detection Rule 3: Brute Force Attack

**Hypothesis:** Multiple consecutive failures followed by success indicates password guessing.

```sql
SELECT 
    s.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.department,
    MIN(f.login_date || ' ' || f.login_time) AS first_failure,
    s.login_date || ' ' || s.login_time AS success_time,
    COUNT(f.event_id) AS failure_count,
    s.source_ip AS success_ip
FROM log_in_attempts s
JOIN log_in_attempts f ON s.username = f.username
    AND f.success = 0
    AND julianday(s.login_date || ' ' || s.login_time) - 
        julianday(f.login_date || ' ' || f.login_time) BETWEEN 0 AND 0.042
LEFT JOIN employees e ON s.username = e.employee_id
WHERE s.success = 1
GROUP BY s.username, s.event_id
HAVING COUNT(f.event_id) >= 5;
```

**Results:**

| username | user_name | department | first_failure | success_time | failure_count | success_ip |
|----------|-----------|------------|---------------|--------------|---------------|------------|
| E004 | David Kim | Sales | 2025-01-15 10:01:00 | 2025-01-15 10:10:55 | 8 | 185.220.101.45 |

**Analysis:** Eight failures in 10 minutes followed by success. The source IP 185.220.101.45 is external (not in 10.x.x.x corporate range). This is a **confirmed brute force compromise**. The attacker now has valid credentials for E004.

### Detection Rule 4: Inactive Account Activity

**Hypothesis:** Any authentication activity on terminated accounts indicates either (a) process failure (account not disabled) or (b) active attack.

```sql
SELECT 
    l.username,
    e.first_name || ' ' || e.last_name AS user_name,
    e.status AS account_status,
    l.login_date || ' ' || l.login_time AS timestamp,
    l.country,
    l.source_ip,
    CASE WHEN l.success = 1 THEN 'SUCCESS' ELSE 'FAILED' END AS outcome
FROM log_in_attempts l
JOIN employees e ON l.username = e.employee_id
WHERE e.status != 'Active';
```

**Results:**

| username | user_name | account_status | timestamp | country | outcome |
|----------|-----------|----------------|-----------|---------|---------|
| E016 | Peter Jackson | Terminated | 2025-01-14 22:15:00 | US | FAILED |
| E016 | Peter Jackson | Terminated | 2025-01-14 22:16:00 | US | FAILED |
| E016 | Peter Jackson | Terminated | 2025-01-15 01:30:00 | RU | SUCCESS |

**Analysis:** This is the most critical finding. A terminated employee's account:
1. Received two failed login attempts from US
2. Three hours later, succeeded from Russia

This indicates the account was **not properly disabled** during offboarding, and an attacker (likely different from the US attempts) successfully authenticated. The Russia IP (95.213.45.67) should be blocked immediately.

---

## Phase 3: Triage and Prioritization

### Consolidated Triage Queue

| Priority | Detection Type | User | Timestamp | Severity | Key Evidence |
|----------|---------------|------|-----------|----------|--------------|
| 1 | INACTIVE_ACCOUNT | E016 | 2025-01-15 01:30:00 | HIGH | SUCCESS from Russia on terminated account |
| 2 | BRUTE_FORCE | E004 | 2025-01-15 10:10:55 | HIGH | 8 failures → success, external IP |
| 3 | IMPOSSIBLE_TRAVEL | E007 | 2025-01-14 08:30:00 | HIGH | DE→US in 4.3 hours |
| 4 | UNFAMILIAR_COUNTRY | E001 | 2025-01-16 03:27:00 | HIGH | CN login, baseline US-only |
| 5 | PASSWORD_SPRAY | E012 | 2025-01-13 04:01:00 | MEDIUM | 25 failures, no success |
| 6 | AFTER_HOURS | E011 | 2025-01-15 02:30:00 | MEDIUM | 02:30 UTC login (unusual for Legal) |

### Action Matrix

| User | Immediate Action | SLA | Confidence |
|------|-----------------|-----|------------|
| E016 | Disable account, block IP 95.213.45.67 | 15 min | HIGH |
| E004 | Force password reset, revoke sessions | 30 min | HIGH |
| E007 | Force password reset, contact user | 1 hour | HIGH |
| E001 | Contact user for verification | 2 hours | MEDIUM |
| E012 | Monitor, no action yet (attack failed) | 4 hours | MEDIUM |
| E011 | Contact user to verify activity | 4 hours | LOW |

---

## Phase 4: Data Integrity Validation

Before executing containment, I verify that target identification is accurate.

### Orphan Devices

```sql
SELECT m.device_id, m.employee_id AS listed_owner, m.operating_system
FROM machines m
LEFT JOIN employees e ON m.employee_id = e.employee_id
WHERE e.employee_id IS NULL;
```

**Result:**

| device_id | listed_owner | operating_system |
|-----------|--------------|------------------|
| DEV-099 | E999 | Windows 10 |

**Impact:** DEV-099 cannot be attributed to any user. If involved in an incident, we cannot notify the owner or verify legitimate use.

### Inventory Mismatch

```sql
SELECT 
    m.device_id,
    m.employee_id AS primary_owner,
    b.employee_id AS backup_owner
FROM machines m
JOIN machines_backup b ON m.device_id = b.device_id
WHERE m.employee_id != b.employee_id;
```

**Result:**

| device_id | primary_owner | backup_owner |
|-----------|---------------|--------------|
| DEV-011 | E011 | E007 |

**Impact:** DEV-011 shows Karen Taylor (E011) in primary inventory but Grace Lee (E007) in backup. **Grace Lee is involved in an impossible travel incident.** If we isolate the wrong device, we either:
- Miss the compromised device entirely, or
- Disrupt an uninvolved employee's work

**Required action:** Manually verify DEV-011 ownership before any containment action.

---

## SIEM Translation: Splunk SPL

For operationalization, here's the brute force detection translated to Splunk:

```spl
index=auth sourcetype=login_events
| stats count(eval(success=0)) AS failures, 
        count(eval(success=1)) AS successes,
        earliest(_time) AS first_attempt,
        latest(_time) AS last_attempt
  BY username, src_ip
| where failures >= 5 AND successes >= 1
| eval time_window_minutes = round((last_attempt - first_attempt) / 60, 1)
| where time_window_minutes <= 60
| table username, src_ip, failures, successes, time_window_minutes
| sort - failures
```

This can be scheduled as a saved search with alert action for SOC notification.

---

## Appendix: Detection Confidence

| Detection Rule | True Positive Rate | False Positive Risk | Tuning Notes |
|----------------|-------------------|---------------------|--------------|
| Unfamiliar Country | High | Medium (travel, VPN) | Cross-reference with HR travel records |
| Impossible Travel | High | Low (VPN can cause) | Add distance calculation for precision |
| Brute Force | High | Low | Threshold 5+ failures is conservative |
| Inactive Account | Very High | Very Low | Should never have activity |
| After-Hours | Medium | High (global teams) | Exclude IT, filter by role |
| Password Spray | Medium | Medium | High threshold reduces noise |

---

## Files in This Repository

```
soc-portfolio/
├── EXECUTIVE_SUMMARY.md     # 1-page findings summary
├── README.md                # This document
├── data/
│   ├── setup_database.sql   # Schema + synthetic data
│   └── security.db          # SQLite database
├── sql/
│   └── detection_queries.sql # All detection views
└── docs/
    └── field_dictionary.md  # Data dictionary
```

---

## Methodology Notes

**Why SQL?** SQL-based hunting works with any data source that can be queried—SIEM, data lake, or direct database access. The logic translates across platforms.

**Limitations acknowledged:**
- Country-level geo only (no city/IP range precision)
- No network flow data (can't assess exfiltration)
- Synthetic data (real environments have more noise)


**What I would add with more data:**
- VPN connection logs (resolve impossible travel false positives)
- Process creation logs (detect post-compromise activity)
- Email logs (correlate phishing with credential compromise)

## Development

This project was built with AI-assisted drafting and scaffolding to accelerate iteration. All code was reviewed, tested, and modified by hand. Final logic, signal weights, safety gates, and architectural decisions are deterministic and human-owned.
