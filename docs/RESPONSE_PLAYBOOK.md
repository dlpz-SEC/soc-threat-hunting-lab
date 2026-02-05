# Incident Response Playbook: Authentication Anomalies

**Version:** 1.0 | **Last Updated:** January 2025 | **Owner:** SOC Team

---

## Playbook Index

| Playbook ID | Trigger Condition | SLA |
|-------------|-------------------|-----|
| AUTH-001 | Terminated account activity | 15 min |
| AUTH-002 | Brute force success | 30 min |
| AUTH-003 | Impossible travel | 1 hour |
| AUTH-004 | Unfamiliar country login | 2 hours |
| AUTH-005 | Password spray (failed) | 4 hours |

---

## AUTH-001: Terminated Account Activity

**Severity:** CRITICAL  
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

**Severity:** HIGH  
**SLA:** 30 minutes to containment

### Trigger
5+ failed login attempts followed by success within 60 minutes for same username

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
  AND login_date >= date('now', '-1 day')
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

**Severity:** HIGH  
**SLA:** 1 hour to triage

### Trigger
Same user with successful logins from two countries where travel time < 12 hours and distance > 500km

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

### VPN False Positive Check
```sql
-- Check if both IPs are known VPN exit nodes
SELECT 
    l.source_ip,
    l.country,
    CASE 
        WHEN l.source_ip LIKE '10.%' THEN 'INTERNAL'
        WHEN l.source_ip IN (SELECT ip FROM vpn_exit_nodes) THEN 'VPN'
        ELSE 'EXTERNAL'
    END AS ip_type
FROM log_in_attempts l
WHERE l.username = '<TARGET_USER>'
  AND l.login_date = '<INCIDENT_DATE>';
```

---

## AUTH-004: Unfamiliar Country Login

**Severity:** MEDIUM-HIGH (context dependent)  
**SLA:** 2 hours to triage

### Trigger
Successful login from country not in user's 30-day baseline

### Severity Adjustment

| Factor | Adjustment |
|--------|------------|
| User is admin/privileged | Upgrade to HIGH |
| Country is high-risk (RU, CN, KP, IR) | Upgrade to HIGH |
| Login time is user's business hours | Downgrade to MEDIUM |
| User department is Travel/Sales | Downgrade to MEDIUM |

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

## AUTH-005: Password Spray (No Success)

**Severity:** MEDIUM  
**SLA:** 4 hours to investigate

### Trigger
10+ failed login attempts for a single account within 24 hours, no success

### Actions

```
□ STEP 1: Monitor account (no immediate lockout)
  - Add to watchlist
  - Alert on any success in next 72h

□ STEP 2: Analyze attack pattern
  - Single IP or distributed?
  - Targeting one account or many?
  - Time pattern suggests automation?

□ STEP 3: Consider proactive reset
  - If password is known weak: Force reset
  - If MFA not enabled: Enroll user

□ STEP 4: Correlate with other accounts
  - Same source IP targeting others?
  - Part of spray campaign?
```

### Query: Identify Spray Campaign
```sql
-- Find if multiple accounts targeted from same IP
SELECT 
    source_ip,
    COUNT(DISTINCT username) AS accounts_targeted,
    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS total_failures,
    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS total_successes
FROM log_in_attempts
WHERE login_date >= date('now', '-1 day')
GROUP BY source_ip
HAVING COUNT(DISTINCT username) > 3 AND total_failures > 10
ORDER BY accounts_targeted DESC;
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
