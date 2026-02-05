# SQL-Based Threat Hunting: Investigation Report

**Analyst:** David | **Date:** January 20, 2025 | **Classification:** Internal Use

---

## Executive Summary

Analysis of 132 authentication events across 22 accounts identified **6 confirmed security incidents** requiring immediate response and **4 data integrity issues** affecting incident response capability.

### Critical Findings (Immediate Action Required)

| Priority | User | Finding | Evidence | Action |
|----------|------|---------|----------|--------|
| **P1** | E016 (Peter Jackson) | **Terminated account compromised** | Successful login from Russia (RU) at 01:30 UTC after 2 failed US attempts | Disable account, forensic review, block source IP 95.213.45.67 |
| **P1** | E004 (David Kim) | **Brute force attack succeeded** | 8 failures → success in 10 min from 185.220.101.45 | Force password reset, revoke sessions, monitor account |
| **P1** | E007 (Grace Lee) | **Impossible travel detected** | Germany → US in 4.3 hours (2025-01-14) | Force password reset, verify user location, review activity |
| **P2** | E001 (Alice Chen) | **Anomalous foreign login** | Success from China (CN) at 03:27 UTC; baseline is US-only | Contact user, force password reset if unauthorized |

### Infrastructure Risks Identified

| Device | Owner | Days Since Patch | Risk | Recommended Action |
|--------|-------|------------------|------|-------------------|
| SRV-001 | svc_backup | 285 | CRITICAL | Isolate, emergency patch |
| DEV-011 | Karen Taylor | 245 | CRITICAL | Patch within 24h |
| DEV-012 | Leo Anderson | 219 | CRITICAL | Patch within 24h |

### Data Integrity Blockers

Before executing containment on DEV-011, resolve ownership conflict:
- **Primary inventory:** Karen Taylor (E011)
- **Backup inventory:** Grace Lee (E007)
- **Impact:** Cannot determine correct owner for device isolation

---

## Detection Summary

```
┌─────────────────────────────────────────────────────────────────┐
│ TRIAGE QUEUE: 13 anomalies detected                             │
├─────────────────────────────────────────────────────────────────┤
│ HIGH severity:   9 events (69%)  ← Immediate response required  │
│ MEDIUM severity: 4 events (31%)  ← Investigate within 4 hours   │
└─────────────────────────────────────────────────────────────────┘

Detection Breakdown:
• Inactive Account Activity:  3 events (terminated user E016)
• Unfamiliar Country Login:   3 events (CN, DE, RU)
• Impossible Travel:          2 events (E001, E007)
• Brute Force Success:        1 event  (E004)
• After-Hours Login:          3 events (investigate correlation)
• Password Spray:             1 event  (25 attempts on E012, no success)
```

---

## Recommended Response Sequence

**Hour 0-1 (Critical Containment):**
1. Disable E016 (terminated account) across all systems
2. Force password reset: E004, E007, E001
3. Block IPs: 185.220.101.45, 95.213.45.67, 203.45.67.89

**Hour 1-4 (Investigation):**
4. Contact E001 (Alice Chen) - verify China login legitimacy
5. Contact E007 (Grace Lee) - verify Germany travel
6. Review E004 session activity post-compromise

**Day 1-2 (Remediation):**
7. Resolve DEV-011 ownership conflict
8. Emergency patch SRV-001 (backup server)
9. Patch DEV-011, DEV-012

**Week 1 (Process Improvement):**
10. Implement offboarding automation (prevent E016 recurrence)
11. Reconcile inventory systems
12. Deploy geo-blocking for unauthorized regions

---

## Methodology

This investigation used SQL-based threat hunting against authentication logs and asset inventory. Detection rules aligned to MITRE ATT&CK:

- **T1078** (Valid Accounts): Detected via impossible travel, unfamiliar location
- **T1110** (Brute Force): Detected via failure-to-success pattern analysis
- **T1078.004** (Cloud Accounts): Detected via terminated account usage

All queries are reproducible; see `sql/detection_queries.sql` for implementation.

---

**Confidence Level:** HIGH - Findings based on direct log evidence with corroborating patterns.

**Limitations:** No network flow data available; unable to determine data exfiltration scope. IP geolocation is country-level only.
