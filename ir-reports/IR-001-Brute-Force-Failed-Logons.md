# IR-001: Brute Force - Multiple Failed Logon Attempts

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | IR-001 |
| **Sentinel Incident ID** | 1, 2, 5, 6 |
| **Date** | 2026-06-11 |
| **Severity** | Medium |
| **Status** | Resolved |
| **Analyst** | Atharva Acharya |
| **MITRE ATT&CK Tactic** | Credential Access |
| **MITRE ATT&CK Technique** | T1110 - Brute Force |

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 22:30:49 | First failed logon attempt detected for account `sentinel-win-vm\fakeuser` |
| 22:30:50 | 20 failed logon attempts (Event ID 4625) recorded within 10 seconds |
| 22:43:00 | Microsoft Sentinel analytics rule triggered — incident created |
| 22:45:00 | Analyst investigation initiated |
| 22:50:00 | Incident confirmed as simulated brute force attack, no lateral movement detected |

---

## Detection

**Detection Source:** Microsoft Sentinel — Scheduled Analytics Rule  
**Rule Name:** Brute Force - Multiple Failed Logon Attempts  
**Log Source:** Windows Security Events via Azure Monitor Agent  
**Event IDs:** 4625 (An account failed to log on)

**KQL Query Used:**
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(30m)
| summarize FailedAttempts = count() by Account, IpAddress, Computer, bin(TimeGenerated, 30m)
| where FailedAttempts > 5
```

**Query Results:**

| Account | IP Address | Computer | Failed Attempts |
|---|---|---|---|
| sentinel-win-vm\fakeuser | ::1 (localhost) | sentinel-win-vm | 20 |

---

## Investigation

### Affected Assets
- **Host:** sentinel-win-vm (Azure VM, West US 2)
- **Target Account:** sentinel-win-vm\fakeuser (non-existent account)
- **Source IP:** ::1 (localhost — attack originated from the machine itself)

### Analysis
Twenty consecutive failed logon attempts were recorded against the non-existent account `fakeuser` within a 10-second window. The source IP of `::1` indicates the attempts originated locally on `sentinel-win-vm`, consistent with a credential stuffing or brute force tool running on the compromised host.

The target account does not exist on the system, suggesting the attacker was using a wordlist or automated tool without prior enumeration of valid accounts.

No successful logon (Event ID 4624) was recorded for `fakeuser` at any point during the incident window.

### Findings
- 20 failed logon attempts against non-existent account `fakeuser`
- No successful authentication achieved
- No lateral movement detected
- No persistence mechanisms identified at this stage
- Attack originated locally — suggests attacker already had local access

---

## Response Actions

| Action | Status |
|---|---|
| Confirmed no successful logon for target account | Complete |
| Reviewed Event ID 4624 logs for any successful authentications | Complete |
| Checked for concurrent suspicious process execution | Complete |
| Verified no new accounts created during incident window | Complete |
| Incident marked as simulated lab activity | Complete |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|---|---|---|---|
| Credential Access | T1110 | T1110.001 - Password Guessing | Repeated failed logon attempts against a target account |

---

## Recommendations

1. Implement account lockout policy — lock accounts after 5 failed attempts within 10 minutes
2. Enable MFA on all accounts with interactive logon rights
3. Alert on any authentication attempts against non-existent accounts
4. Deploy privileged access workstations for administrative accounts

---

## Lessons Learned

The analytics rule successfully detected the brute force pattern within one rule run cycle (5 minutes). The entity mapping correctly identified the target account and host, enabling rapid triage. Threshold of 5 failed attempts in 30 minutes is appropriate for a server environment — consider lowering to 3 for privileged accounts.
