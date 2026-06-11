# IR-002: New Local User Account Created

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | IR-002 |
| **Sentinel Incident ID** | 3 |
| **Date** | 2026-06-11 |
| **Severity** | Medium |
| **Status** | Resolved |
| **Analyst** | Atharva Acharya |
| **MITRE ATT&CK Tactic** | Persistence |
| **MITRE ATT&CK Technique** | T1136.001 - Create Account: Local Account |

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 22:43:44 | New local user account `backdooruser` created by `labadmin` (Event ID 4720) |
| 22:47:00 | Microsoft Sentinel analytics rule triggered — incident created |
| 22:48:00 | Analyst investigation initiated |
| 22:55:00 | Account confirmed as simulated persistence mechanism, no further propagation detected |

---

## Detection

**Detection Source:** Microsoft Sentinel — Scheduled Analytics Rule  
**Rule Name:** New Local User Account Created  
**Log Source:** Windows Security Events via Azure Monitor Agent  
**Event IDs:** 4720 (A user account was created)

**KQL Query Used:**
```kql
SecurityEvent
| where EventID == 4720
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, TargetAccount, Computer, EventID
```

**Query Results:**

| Time | Account (Creator) | Target Account | Computer |
|---|---|---|---|
| 2026-06-11 22:43:44 | sentinel-win-vm\labadmin | sentinel-win-vm\backdooruser | sentinel-win-vm |

---

## Investigation

### Affected Assets
- **Host:** sentinel-win-vm (Azure VM, West US 2)
- **Creating Account:** sentinel-win-vm\labadmin (local administrator)
- **New Account:** sentinel-win-vm\backdooruser

### Analysis
A new local user account named `backdooruser` was created by `labadmin` at 22:43:44 UTC. The account name is consistent with an attacker establishing a persistence mechanism via a backdoor account. Creation of local accounts outside of an approved change management process is a strong indicator of compromise.

Review of subsequent events revealed that `backdooruser` was added to the local Administrators group within 4 minutes of creation (Event ID 4732 at 22:47:59 UTC), escalating the account to full administrative privileges on the host. This two-step pattern — account creation followed by privilege escalation — is characteristic of an attacker establishing persistent, high-privilege access.

### Findings
- Unauthorised local account `backdooruser` created outside approved process
- Account immediately granted administrative privileges (see IR-003)
- No evidence of the account being used for interactive logon post-creation
- Account persists on system until remediation

---

## Response Actions

| Action | Status |
|---|---|
| Identified account creator (`labadmin`) | Complete |
| Confirmed account added to Administrators group | Complete |
| Checked for interactive logon events for `backdooruser` | Complete |
| Disabled account pending investigation | Complete |
| Correlated with IR-003 (privilege escalation) | Complete |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|---|---|---|---|
| Persistence | T1136 | T1136.001 - Local Account | Creation of a local user account to maintain persistent access |

---

## Recommendations

1. Restrict local account creation to domain administrators only via Group Policy
2. Alert on any local account creation and require change ticket correlation
3. Audit existing local accounts on all endpoints — remove any unauthorised accounts
4. Implement Privileged Identity Management for administrative account creation

---

## Lessons Learned

The two-minute detection window between account creation and alert firing is acceptable. The critical insight is the correlation between this incident and IR-003 — account creation and privilege escalation occurring within minutes of each other should auto-correlate into a single high-severity incident. Consider implementing alert grouping in Sentinel to combine T1136 and T1098 events from the same host within a short time window.
