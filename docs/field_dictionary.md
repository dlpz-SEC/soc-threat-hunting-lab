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

## Key Relationships

```
log_in_attempts.username  →  employees.employee_id
machines.employee_id      →  employees.employee_id
machines.device_id        →  machines_backup.device_id (integrity check)
```

## Data Quality Assumptions

- All timestamps are UTC
- Country codes are ISO 3166-1 alpha-2
- Source IPs may be internal (10.x.x.x) or external
- Employee status reflects current state (not historical)
