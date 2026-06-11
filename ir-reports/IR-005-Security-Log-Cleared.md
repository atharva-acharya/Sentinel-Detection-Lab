# IR-005: Security Event Log Cleared

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | IR-005 |
| **Sentinel Incident ID** | 6 |
| **Date** | 2026-06-11 |
| **Severity** | High |
| **Status** | Resolved |
| **Analyst** | Atharva Acharya |
| **MITRE ATT&CK Tactic** | Defense Evasion |
| **MITRE ATT&CK Technique** | T1070.001 - Indicator Removal: Clear Windows Event Logs |

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 22:56:43 | Windows Security event log cleared on `sentinel-win-vm` (Event ID 1102) |
| 23:01:00 | Microsoft Sentinel analytics rule triggered — High severity incident created |
| 23:02:00 | Analyst investigation initiated |
| 23:10:00 | Confirmed as deliberate log clearing, prior events preserved in Sentinel workspace |

---

## Detection

**Detection Source:** Microsoft Sentinel — Scheduled Analytics Rule  
**Rule Name:** Security Event Log Cleared  
**Log Source:** Windows Security Events via Azure Monitor Agent  
**Event IDs:** 1102 (The audit log was cleared)

**KQL Query Used:**
```kql
SecurityEvent
| where EventID == 1102
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, Computer, Activity
```

**Query Results:**

| Time | Computer | Activity |
|---|---|---|
| 2026-06-11 22:56:43 | sentinel-win-vm | 1102 - The audit log was cleared |

---

## Investigation

### Affected Assets
- **Host:** sentinel-win-vm (Azure VM, West US 2)
- **Log Cleared:** Windows Security Event Log
- **Method:** `wevtutil cl Security` executed via PowerShell

### Analysis
At 22:56:43 UTC, the Windows Security event log was cleared on `sentinel-win-vm`. Event ID 1102 is generated when the Security log is cleared and is itself captured by the Azure Monitor Agent before the log wipe takes effect — this is a critical design feature of cloud-based SIEM ingestion that prevents local log clearing from destroying evidence.

The log clearing occurred approximately 4 minutes after the reconnaissance activity identified in IR-004, which is consistent with an attacker completing their initial access objectives and attempting to remove forensic evidence before exiting or establishing persistence.

Key finding: **All prior events were already ingested into the Sentinel workspace before the log was cleared.** The attacker's attempt to destroy evidence was unsuccessful because cloud SIEM ingestion operates continuously and independently of local log storage. Events from IR-001 through IR-004 remain fully available in the Log Analytics workspace.

This is a textbook example of why cloud-based SIEM with near-real-time ingestion is a critical defensive control. Local log clearing — a technique that would have been highly effective against on-premises SIEM solutions — is entirely ineffective against a properly configured Sentinel deployment.

### Findings
- Security event log cleared at 22:56:43 UTC using `wevtutil cl Security`
- Log clearing occurred post-reconnaissance — consistent with attacker cleanup
- All prior events (IR-001 through IR-004) preserved in Sentinel workspace
- No evidence of System or Application log clearing
- Single Event ID 1102 recorded — confirms one deliberate clearing action

---

## Response Actions

| Action | Status |
|---|---|
| Confirmed Event ID 1102 captured in Sentinel before local log cleared | Complete |
| Verified all prior incident events preserved in Log Analytics workspace | Complete |
| Reviewed for additional log clearing attempts (System, Application logs) | Complete |
| Confirmed wevtutil execution via Event ID 4688 process creation logs | Complete |
| Correlated with full incident timeline IR-001 through IR-005 | Complete |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|---|---|---|---|
| Defense Evasion | T1070 | T1070.001 - Clear Windows Event Logs | Clearing the Windows Security event log using wevtutil to destroy forensic evidence |

---

## Recommendations

1. Forward all event logs (Security, System, Application) to Sentinel — not just Security
2. Alert on clearing of any Windows event log, not just Security
3. Restrict `wevtutil` execution to SYSTEM account only via AppLocker policy
4. Implement tamper protection on log forwarding agent to prevent agent-level evidence destruction
5. Configure Log Analytics workspace data retention to 90 days minimum for forensic investigations

---

## Lessons Learned

This incident demonstrates the single most important advantage of cloud-based SIEM over on-premises solutions: local log clearing cannot destroy evidence that has already been ingested. The attacker's use of `wevtutil cl Security` — a technique that would have been highly effective a decade ago — had zero impact on the investigation because every event was already in Sentinel.

This finding should be documented as a key selling point of the architecture in the lab README. For any interviewer asking why you chose cloud SIEM, this is the answer: evidence preservation is guaranteed regardless of what the attacker does to the endpoint.
