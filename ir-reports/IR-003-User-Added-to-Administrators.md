# IR-003: User Added to Local Administrators Group

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | IR-003 |
| **Sentinel Incident ID** | 4 |
| **Date** | 2026-06-11 |
| **Severity** | High |
| **Status** | Resolved |
| **Analyst** | Atharva Acharya |
| **MITRE ATT&CK Tactic** | Privilege Escalation |
| **MITRE ATT&CK Technique** | T1098 - Account Manipulation |

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 22:43:44 | Account `backdooruser` created (IR-002) |
| 22:47:59 | `backdooruser` added to local Administrators group by `labadmin` (Event ID 4732) |
| 22:52:00 | Microsoft Sentinel analytics rule triggered — High severity incident created |
| 22:53:00 | Analyst investigation initiated |
| 23:00:00 | Confirmed privilege escalation, correlated with IR-002, account remediated |

---

## Detection

**Detection Source:** Microsoft Sentinel — Scheduled Analytics Rule  
**Rule Name:** User Added to Administrators Group  
**Log Source:** Windows Security Events via Azure Monitor Agent  
**Event IDs:** 4732 (A member was added to a security-enabled local group)

**KQL Query Used:**
```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName == "Administrators"
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, TargetAccount, TargetUserName, Computer
```

**Query Results:**

| Time | Account (Actor) | Target Group | Computer |
|---|---|---|---|
| 2026-06-11 22:47:59 | sentinel-win-vm\labadmin | Builtin\Administrators | sentinel-win-vm |

---

## Investigation

### Affected Assets
- **Host:** sentinel-win-vm (Azure VM, West US 2)
- **Acting Account:** sentinel-win-vm\labadmin
- **Escalated Account:** backdooruser
- **Target Group:** Builtin\Administrators

### Analysis
At 22:47:59 UTC, `labadmin` added `backdooruser` to the local Administrators group on `sentinel-win-vm`. This event occurred 4 minutes and 15 seconds after the account was created (IR-002), indicating a deliberate two-stage persistence and privilege escalation sequence.

Membership in the local Administrators group grants full unrestricted access to the host, including the ability to:
- Read and modify all files and registry keys
- Install software and services
- Create additional accounts
- Clear event logs
- Dump credentials from LSASS

This event was rated High severity due to the direct impact on host integrity and the correlation with a newly created unauthorised account. The pattern of creating a named "backdoor" account and immediately granting it administrative rights is a well-documented attacker technique for establishing persistent privileged access.

### Findings
- `backdooruser` granted full local administrative privileges
- Escalation performed by `labadmin` — compromised administrator account likely vector
- Four-minute gap between account creation and privilege escalation suggests scripted or deliberate action
- No evidence of `backdooruser` being used for further activity post-escalation in this incident window

---

## Response Actions

| Action | Status |
|---|---|
| Identified escalating account (`labadmin`) | Complete |
| Confirmed `backdooruser` membership in Administrators group | Complete |
| Removed `backdooruser` from Administrators group | Complete |
| Disabled `backdooruser` account | Complete |
| Reviewed `labadmin` activity for signs of compromise | Complete |
| Correlated with IR-002 (account creation) | Complete |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|---|---|---|---|
| Privilege Escalation | T1098 | — | Adding an account to a privileged local group to gain elevated access |
| Persistence | T1098 | — | Maintaining administrative access via a backdoor account |

---

## Recommendations

1. Implement Just-In-Time (JIT) access for all administrative group membership changes
2. Alert on all Administrators group membership changes — zero tolerance policy
3. Require dual approval for any local group modification on production systems
4. Audit Administrators group membership on all endpoints weekly
5. Consider removing local Administrators group usage entirely in favour of LAPS and PAM solutions

---

## Lessons Learned

This incident demonstrates the importance of correlating related alerts. IR-002 and IR-003 together tell a complete story — account creation followed by privilege escalation within minutes — but were detected as separate incidents. Implementing alert grouping by host and time window would consolidate these into a single High-severity incident, reducing analyst triage time and improving the signal-to-noise ratio.
