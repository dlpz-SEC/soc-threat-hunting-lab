# Field Dictionary

## log_in_attempts

| Field | Type | Description | Detection Use |
|-------|------|-------------|---------------|
| event_id | INT | Unique event identifier | Join key for correlation |
| username | VARCHAR | User/account identifier | Links to employees.employee_id |
| login_date | DATE | Date of attempt (UTC) | Time-based filtering |
| login_time | TIME | Time of attempt (UTC) | After-hours detection |
| country | VARCHAR(8) | ISO country code from geo-IP | Location anomaly detection |
| success | INT | 1=success, 0=failure | Brute force pattern detection |
| source_ip | VARCHAR(45) | Source IP address | Threat intel correlation |

## employees

| Field | Type | Description | Detection Use |
|-------|------|-------------|---------------|
| employee_id | VARCHAR | Primary key, matches username | Join to auth logs |
| first_name | VARCHAR | Employee first name | Alert context |
| last_name | VARCHAR | Employee last name | Alert context |
| department | VARCHAR | Organizational unit | Privilege assessment |
| office | VARCHAR | Physical location | Expected geo baseline |
| status | VARCHAR | Active/Terminated/Disabled | Inactive account detection |
| hire_date | DATE | Employment start | Account age context |

## machines

| Field | Type | Description | Detection Use |
|-------|------|-------------|---------------|
| device_id | VARCHAR | Unique asset identifier | Containment targeting |
| employee_id | VARCHAR | Assigned owner | Links to employees |
| operating_system | VARCHAR | OS name and version | Vulnerability assessment |
| os_patch_date | DATE | Last patch applied | Patch posture risk |
| device_type | VARCHAR | Laptop/Workstation/Server | Asset criticality |

## machines_backup

| Field | Type | Description | Detection Use |
|-------|------|-------------|---------------|
| device_id | VARCHAR | Asset identifier | Cross-reference with primary |
| employee_id | VARCHAR | Owner per backup system | Integrity validation |

## hunt_config

Single source of truth for the hunt's dates and thresholds. Detection views read
these via scalar subqueries instead of hardcoding literals (SQLite views cannot
take parameters).

| Field | Type | Description | Detection Use |
|-------|------|-------------|---------------|
| key | TEXT | Config name (e.g. `baseline_end`, `max_travel_speed_kmh`) | Referenced by every view |
| value | TEXT | Config value (cast per use) | Dates, windows, thresholds |

## ground_truth / ground_truth_assets

Planted-anomaly labels that make measurement possible (`scripts/compute_metrics.py`).

| Field | Type | Description | Detection Use |
|-------|------|-------------|---------------|
| event_id | INT | FK to log_in_attempts | Per-event precision/recall |
| is_malicious | INT | 1 if part of a planted attack | Precision denominator |
| anomaly_class | TEXT | e.g. `impossible_travel`, `benign` | Class-scoped recall |
| is_anchor | INT | 1 = a correct rule MUST flag this | Recall numerator |
| campaign_id | TEXT | Groups multi-event attacks | Campaign-grain recall |
| asset_id | TEXT | (assets) device/employee id | Integrity metric |

## ip_enrichment / country_distance / travel_exceptions

Static reference data (`data/enrichment.sql`), mirroring ADTE's offline intel.

| Field | Type | Description | Detection Use |
|-------|------|-------------|---------------|
| ip_prefix | TEXT | Dotted prefix (e.g. `185.220.101.`) | Triage-queue intel join |
| is_malicious / confidence | INT / REAL | Reputation, 0.0–1.0 | Source scoring |
| source / tags | TEXT | Feed name; `tor-exit`, `scanner`, `c2` | Naming attacker infra |
| distance_km | INT | Country-centroid great-circle km | Impossible-travel velocity |
| rationale | TEXT | Why a country pair is downgraded | Documented tuning |

## Key Relationships

```
log_in_attempts.username  →  employees.employee_id
log_in_attempts.event_id  →  ground_truth.event_id
log_in_attempts.source_ip →  ip_enrichment.ip_prefix (LIKE prefix)
machines.employee_id      →  employees.employee_id
machines.device_id        →  machines_backup.device_id (integrity check)
```

## Data Quality Assumptions

- All timestamps are UTC
- Country codes are ISO 3166-1 alpha-2
- Source IPs may be internal (10.x.x.x) or external
- Employee status reflects current state (not historical)
- The `username → employee_id` join is logical only (no FK); DEV-099 → E999 is a
  deliberate orphan, so foreign keys are intentionally not enforced at load time
