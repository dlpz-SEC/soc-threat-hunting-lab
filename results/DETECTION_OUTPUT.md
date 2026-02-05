# Detection Results: January 20, 2025

This file contains actual query output from the detection rules run against the security database.

---

## Dataset Summary

```
table_name  | count
------------|------
Logins      | 132  
Employees   | 22   
Machines    | 18   
```

---

## Baseline: User Geographic Patterns

```
username  | known_countries | country_count
----------|-----------------|---------------
E001      | US              | 1            
E002      | US,CA           | 2            
E003      | US              | 1            
E004      | US              | 1            
E005      | US              | 1            
E006      | US              | 1            
E007      | US              | 1            
E008      | US              | 1            
svc_backup| US              | 1            
svc_monitor| US             | 1            
```

**Finding:** All users except E002 have single-country baselines. E002 shows legitimate US/CA travel pattern.

---

## Baseline: Patch Risk Assessment

```
device_id | owner_name      | department         | operating_system     | days_since_patch | patch_risk
----------|-----------------|--------------------|--------------------- |------------------|----------
SRV-001   | Service Backup  | IT Infrastructure  | Windows Server 2019  | 285              | CRITICAL  
DEV-011   | Karen Taylor    | Legal              | Windows 10           | 245              | CRITICAL  
DEV-012   | Leo Anderson    | Sales              | Windows 10           | 219              | CRITICAL  
DEV-099   | (orphan)        |                    | Windows 10           | 172              | WARNING   
```

**Finding:** 3 devices exceed 180-day patch threshold. SRV-001 is infrastructure-critical.

---

## Detection: Unfamiliar Country Login (HIGH)

```
username | user_name      | department | timestamp           | anomaly_country | baseline_countries
---------|----------------|------------|---------------------|-----------------|-------------------
E001     | Alice Chen     | Finance    | 2025-01-16 03:27:00 | CN              | US                
E007     | Grace Lee      | Finance    | 2025-01-14 08:30:00 | DE              | US                
E016     | Peter Jackson  | Sales      | 2025-01-15 01:30:00 | RU              | (none)            
```

**Finding:** 3 anomalous foreign logins detected. E016 (terminated) with Russia login is critical.

---

## Detection: Impossible Travel (HIGH)

```
username | user_name   | timestamp_1          | country_1 | timestamp_2          | country_2 | hours_apart
---------|-------------|----------------------|-----------|----------------------|-----------|------------
E001     | Alice Chen  | 2025-01-16 03:27:00  | CN        | 2025-01-16 14:15:00  | US        | 10.8       
E007     | Grace Lee   | 2025-01-14 08:30:00  | DE        | 2025-01-14 12:45:00  | US        | 4.3        
```

**Finding:** 2 impossible travel events. E007's 4.3-hour DE→US is physically impossible (min flight ~8h).

---

## Detection: Brute Force Success (HIGH)

```
username | user_name  | department | first_failure        | success_time         | failure_count | success_ip
---------|------------|------------|----------------------|----------------------|---------------|---------------
E004     | David Kim  | Sales      | 2025-01-15 10:01:00  | 2025-01-15 10:10:55  | 8             | 185.220.101.45
```

**Finding:** Confirmed brute force. 8 failures → success in 10 minutes from external IP.

---

## Detection: Password Spray (MEDIUM)

```
username | user_name     | login_date | failure_count | first_attempt | last_attempt
---------|---------------|------------|---------------|---------------|-------------
E012     | Leo Anderson  | 2025-01-13 | 25            | 04:01:00      | 04:07:00    
```

**Finding:** 25 failed attempts in 6 minutes. Attack failed (no success), but account was targeted.

---

## Detection: Inactive Account Activity (HIGH)

```
username | user_name      | account_status | timestamp           | country | outcome
---------|----------------|----------------|---------------------|---------|--------
E016     | Peter Jackson  | Terminated     | 2025-01-14 22:15:00 | US      | FAILED 
E016     | Peter Jackson  | Terminated     | 2025-01-14 22:16:00 | US      | FAILED 
E016     | Peter Jackson  | Terminated     | 2025-01-15 01:30:00 | RU      | SUCCESS
```

**Finding:** CRITICAL. Terminated account had successful login from Russia after two US failures.

---

## Detection: After-Hours Login (MEDIUM)

```
username | user_name      | department | timestamp           | login_hour | severity
---------|----------------|------------|---------------------|------------|--------
E001     | Alice Chen     | Finance    | 2025-01-16 03:27:00 | 3          | MEDIUM 
E011     | Karen Taylor   | Legal      | 2025-01-15 02:30:00 | 2          | MEDIUM 
E016     | Peter Jackson  | Sales      | 2025-01-15 01:30:00 | 1          | MEDIUM 
```

**Finding:** 3 after-hours logins. E001 and E016 correlate with other HIGH detections.

---

## Integrity: Orphan Devices

```
device_id | listed_owner | operating_system | issue
----------|--------------|------------------|----------------------------------------------
DEV-099   | E999         | Windows 10       | Device has no valid owner in employee directory
```

**Finding:** 1 orphan device. Cannot be attributed if involved in incident.

---

## Integrity: Inventory Mismatch

```
device_id | primary_owner | primary_owner_name | backup_owner | backup_owner_name | issue
----------|---------------|--------------------|--------------|-------------------|------
DEV-011   | E011          | Karen Taylor       | E007         | Grace Lee         | Ownership conflict
```

**Finding:** DEV-011 ownership conflicts between systems. Grace Lee (E007) is involved in impossible travel incident—must resolve before containment.

---

## Consolidated Triage Queue

| Priority | Type | User | Timestamp | Severity | Action Required |
|----------|------|------|-----------|----------|-----------------|
| 1 | INACTIVE_ACCOUNT | E016 | 2025-01-15 01:30:00 | HIGH | Disable immediately |
| 2 | BRUTE_FORCE | E004 | 2025-01-15 10:10:55 | HIGH | Password reset |
| 3 | IMPOSSIBLE_TRAVEL | E007 | 2025-01-14 08:30:00 | HIGH | Password reset, verify |
| 4 | UNFAMILIAR_COUNTRY | E001 | 2025-01-16 03:27:00 | HIGH | Contact user |
| 5 | PASSWORD_SPRAY | E012 | 2025-01-13 04:01:00 | MEDIUM | Monitor |
| 6 | AFTER_HOURS | E011 | 2025-01-15 02:30:00 | MEDIUM | Investigate |

---

## Verification Command

To reproduce these results:

```bash
cd soc-portfolio
sqlite3 data/security.db < sql/detection_queries.sql
sqlite3 -header -column data/security.db "SELECT * FROM v_triage_queue;"
```
