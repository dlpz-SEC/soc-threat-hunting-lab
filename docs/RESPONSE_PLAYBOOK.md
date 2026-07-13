# Incident Response Playbook: Authentication Anomalies

**Version:** 2.0 | **Owner:** SOC Team

> **Date convention:** verification queries below use
> `(SELECT value FROM hunt_config WHERE key = 'asof_date')` for the hunt's
> "now", matching the detection views. In a live SOC, substitute `date('now')`
> or your SIEM's time-range picker. The lab pins the as-of date so results are
> reproducible.

---

## Playbook Index

| Playbook ID | Trigger Condition | ATT&CK | SLA |
|-------------|-------------------|--------|-----|
| AUTH-001 | Terminated account activity | T1078.002 | 15 min |
| AUTH-002 | Brute force success | T1110.001 | 30 min |
| AUTH-003 | Impossible travel | T1078 | 1 hour |
| AUTH-004 | Unfamiliar country login | T1078 | 2 hours |
| AUTH-005 | Password spray (one source, many accounts) | T1110.003 | 4 hours |
| AUTH-006 | Failed brute force (one account, no success) | T1110.001 | 4 hours |

---

## AUTH-001: Terminated Account Activity

**Severity:** CRITICAL | **ATT&CK:** T1078.002 (Valid Accounts: Domain Accounts)
**SLA:** 15 minutes to containment

### Trigger
Any authentication event (success OR failure) on an account with status = 'Terminated' or 'Disabled'

### Immediate Actions (0-15 min)

```
□ STEP 1: Disable account in all identity systems
  - Active Directory: Disable-ADAccount -Identity <username>
  - Okta/Azure AD: Suspend user via admin console
  - VPN: Revoke certificates
  
□ STEP 2: Terminate active sessions
  - AD: Reset password to random value
  - Cloud: Revoke OAuth tokens
  - VPN: Force disconnect

□ STEP 3: Block source IP at perimeter
  - Add to firewall block list (temporary 24h)
  - Add to SIEM watchlist

□ STEP 4: Preserve evidence
  - Export authentication logs for username (30 day window)
  - Screenshot current account status
```

### Investigation (15 min - 2 hours)

```
□ STEP 5: Determine root cause
  - Was account properly disabled during offboarding? (Check ServiceNow ticket)
  - When was employee terminated? (HR system)
  - Was account re-enabled by anyone? (AD audit logs)

□ STEP 6: Assess exposure
  - What systems does this account have access to?
  - Were any resources accessed after termination?
  - Any data exfiltration indicators?

□ STEP 7: Identify attacker
  - Geo-locate source IP
  - Check if IP appears in threat intelligence
  - Correlate with any other accounts from same IP
```

### Escalation Criteria
- Successful login: Escalate to Incident Commander
- Access to sensitive data: Engage Legal/Privacy
- Evidence of data exfiltration: Engage CIRT

---

## AUTH-002: Brute Force Success

**Severity:** HIGH | **ATT&CK:** T1110.001 (Brute Force: Password Guessing)
**SLA:** 30 minutes to containment

### Trigger
5+ *uninterrupted* failed login attempts followed by success within 60 minutes
for the same username (detection: `v_detect_brute_force`, which enforces the
no-intervening-success condition).

### Immediate Actions (0-30 min)

```
□ STEP 1: Force password reset
  - AD: Set-ADAccountPassword -Reset -Identity <username>
  - Notify user via alternate channel (phone, Slack DM)
  
□ STEP 2: Revoke all sessions
  - Invalidate Kerberos tickets
  - Revoke cloud session tokens
  - Force re-authentication

□ STEP 3: Block attack source
  - Add source IP to temporary block (24h)
  - If Tor exit node: Consider Tor blocking policy

□ STEP 4: Enable enhanced monitoring
  - Add username to watchlist (7 days)
  - Alert on any new login from non-baseline location
```

### Verification Script
```sql
-- Confirm brute force pattern
SELECT
    login_date, login_time, success, source_ip
FROM log_in_attempts
WHERE username = '<TARGET_USER>'
  AND login_date >= (SELECT value FROM hunt_config WHERE key = 'detection_start')
ORDER BY login_date, login_time;
```

### Investigation Checklist

```
□ STEP 5: Assess post-compromise activity
  - What did the attacker do after successful login?
  - Any file access? Email access? Privilege escalation?
  - Check VPN, O365, internal app logs

□ STEP 6: Determine credential source
  - Was password in known breach database?
  - Weak password? (Check against policy)
  - Phishing campaign targeting user?

□ STEP 7: Remediation
  - User security awareness follow-up
  - Consider MFA enrollment if not present
  - Review account privileges
```

---

## AUTH-003: Impossible Travel

**Severity:** HIGH | **ATT&CK:** T1078 (Valid Accounts)
**SLA:** 1 hour to triage

### Trigger
Consecutive successful logins from two countries whose **required velocity
exceeds 900 km/h** (`v_detect_impossible_travel`). The detection exposes
`required_kmh` per case, so triage starts from a number, not a hunch. Pairs in
`travel_exceptions` (e.g. the US↔CA corridor) arrive pre-downgraded to MEDIUM
with a rationale — they are surfaced, never silently suppressed.

### Triage Decision Tree

```
                    [Impossible Travel Alert]
                             │
                             ▼
              ┌──────────────────────────────┐
              │ Is user on approved travel?  │
              └──────────────────────────────┘
                      │              │
                     YES            NO
                      │              │
                      ▼              ▼
              ┌────────────┐  ┌─────────────────┐
              │ Check VPN  │  │ Contact user    │
              │ exit nodes │  │ via phone/Slack │
              └────────────┘  └─────────────────┘
                      │              │
                      ▼              ▼
              ┌────────────┐  ┌─────────────────┐
              │ VPN caused │  │ User confirms   │
              │ false pos? │  │ one login was   │
              └────────────┘  │ not them?       │
                      │       └─────────────────┘
                     YES             │
                      │             YES
                      ▼              │
              [Close as FP]          ▼
                            [Escalate: Credential
                             Compromise Confirmed]
```

### Immediate Actions (if confirmed compromise)

```
□ STEP 1: Force password reset
□ STEP 2: Revoke all sessions  
□ STEP 3: Review activity from suspicious location
  - What was accessed?
  - Any configuration changes?
  - Any data downloaded?
```

### Source enrichment check
```sql
-- Classify both source IPs against the static intel table (ip_enrichment).
-- Replaces the earlier reference to a vpn_exit_nodes table that never existed
-- in the schema.
SELECT
    l.source_ip,
    l.country,
    CASE
        WHEN l.source_ip LIKE '10.%' THEN 'INTERNAL'
        WHEN ie.tags IS NOT NULL THEN ie.tags     -- e.g. tor-exit, scanner, c2
        ELSE 'EXTERNAL (no intel match)'
    END AS ip_classification,
    ie.source AS intel_source, ie.confidence
FROM log_in_attempts l
LEFT JOIN ip_enrichment ie ON l.source_ip LIKE ie.ip_prefix || '%'
WHERE l.username = '<TARGET_USER>'
  AND l.login_date = '<INCIDENT_DATE>';
```
A Tor/scanner/c2 tag on either leg strengthens the compromise case; an
unenriched external IP is not exonerating (feeds are incomplete — E016's RU
source is a real example of a gap).

---

## AUTH-004: Unfamiliar Country Login

**Severity:** MEDIUM-HIGH (context dependent) | **ATT&CK:** T1078 (Valid Accounts)
**SLA:** 2 hours to triage

### Trigger
Successful login from a country not in the user's baseline
(`v_detect_unfamiliar_country`). Accounts with **no** baseline (new/dormant)
fire a separate, lower-confidence branch — treat those as "verify the account
came back online", not "compromise".

### Severity Adjustment

| Factor | Adjustment | Implemented in view? |
|--------|------------|----------------------|
| Country is high-risk (RU, CN, KP, IR) | Upgrade to HIGH | **Yes** — the view emits HIGH for these |
| User is admin/privileged | Upgrade to HIGH | No — analyst judgment (no privilege field in the dataset) |
| Login time is user's business hours | Downgrade to MEDIUM | No — analyst judgment; cross-check AUTH-003/after-hours |
| User department is Travel/Sales | Downgrade to MEDIUM | No — analyst judgment |

### Triage Steps

```
□ STEP 1: Check travel records
  - Query HR travel system or expense reports
  - Check Slack/email for travel mentions

□ STEP 2: Contact user (if no travel record)
  - Phone call preferred (email may be compromised)
  - "Did you log in from [COUNTRY] at [TIME]?"

□ STEP 3: Decision
  - Confirmed legitimate: Document, close, update baseline
  - Unconfirmed/denied: Treat as compromise, execute AUTH-002
```

---

## AUTH-005: Password Spray (One Source, Many Accounts)

**Severity:** MEDIUM (HIGH if any success) | **ATT&CK:** T1110.003 (Password Spraying)
**SLA:** 4 hours to investigate

### Trigger
One source IP fails against **≥ 5 distinct accounts** in a day
(`v_detect_password_spray`). This is the defining shape of a spray — breadth,
not depth. The per-source grouping below is the **primary detection**, not a
follow-up correlation (the previous version keyed on a single account, which
could never see a spray at all).

### Actions

```
□ STEP 1: Enrich and block the source
  - Classify source_ip against ip_enrichment (scanner/c2/tor-exit)
  - Block at perimeter if confirmed hostile (24h, then review)

□ STEP 2: Check for ANY success from the source
  - A single success amid a spray = live compromise -> escalate to AUTH-002
  - Query: SELECT * FROM v_detect_password_spray WHERE successes > 0;

□ STEP 3: Scope the target set
  - List every account the source touched (usernames column)
  - Proactively reset any that lack MFA

□ STEP 4: Hunt for the same source on other days / other IPs in the range
```

### Query: Spray campaigns (this is the detection view)
```sql
SELECT source_ip, login_date, accounts_targeted, total_failures, successes, usernames
FROM v_detect_password_spray
ORDER BY accounts_targeted DESC;
```

---

## AUTH-006: Failed Brute Force (One Account, No Success)

**Severity:** MEDIUM | **ATT&CK:** T1110.001 (Brute Force: Password Guessing)
**SLA:** 4 hours to investigate

### Trigger
≥ 10 failed attempts against a **single** account from a single source in a day,
with **no success** (`v_detect_bruteforce_failed`). This is brute force that did
not land — distinct from AUTH-002 (which succeeded) and AUTH-005 (many accounts).

### Actions

```
□ STEP 1: Confirm no success slipped through
  - Query v_detect_bruteforce_failed excludes any source that also succeeded;
    double-check the account's full day of activity

□ STEP 2: Assess password strength / MFA
  - If the password is weak or MFA is absent, proactively reset/enroll

□ STEP 3: Enrich and monitor the source
  - Classify source_ip; watchlist the account for 72h for a delayed success
```

---

## Data Integrity Pre-Flight Checklist

**Before taking any containment action on a device, verify:**

```
□ Device ownership matches in both inventory systems
  Query: SELECT * FROM v_inventory_mismatch WHERE device_id = '<TARGET>';

□ User account status is current
  Query: SELECT status, department FROM employees WHERE employee_id = '<USER>';

□ Device is actually assigned (not orphaned)
  Query: SELECT * FROM v_orphan_devices WHERE device_id = '<TARGET>';

□ If any check fails: STOP and escalate to IT Asset Management
```

---

## Escalation Matrix

| Condition | Escalate To | Method |
|-----------|-------------|--------|
| Any confirmed compromise | SOC Lead | Slack #soc-alerts |
| Executive account involved | CISO | Phone |
| Data exfiltration suspected | Legal + CIRT | Email + Phone |
| Multiple accounts compromised | Incident Commander | War room |
| Attack ongoing (active session) | SOC Lead | Immediate |

---

## Post-Incident Actions

After containment, for every incident:

```
□ Document timeline in ticketing system
□ Preserve all evidence (logs, screenshots)
□ Update detection rules if gap found
□ User security awareness if credential issue
□ Process improvement ticket if offboarding failure
□ Threat intel submission if new IOC discovered
```
