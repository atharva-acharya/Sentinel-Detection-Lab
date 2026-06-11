# IR-004: Suspicious Reconnaissance Commands Detected

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | IR-004 |
| **Sentinel Incident ID** | 5 |
| **Date** | 2026-06-11 |
| **Severity** | Medium |
| **Status** | Resolved |
| **Analyst** | Atharva Acharya |
| **MITRE ATT&CK Tactic** | Discovery |
| **MITRE ATT&CK Technique** | T1082 - System Information Discovery |

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 22:52:30 | `whoami.exe` executed by `labadmin` (Event ID 4688) |
| 22:52:30 | `ipconfig.exe` executed by `labadmin` (Event ID 4688) |
| 22:52:30 | `systeminfo.exe` executed by `labadmin` (Event ID 4688) |
| 22:52:30 | `net.exe` executed for user and group enumeration (Event ID 4688) |
| 22:57:00 | Microsoft Sentinel analytics rule triggered — incident created |
| 22:58:00 | Analyst investigation initiated |
| 23:05:00 | Confirmed as simulated reconnaissance activity, no data exfiltration detected |

---

## Detection

**Detection Source:** Microsoft Sentinel — Scheduled Analytics Rule  
**Rule Name:** Suspicious Reconnaissance Commands Detected  
**Log Source:** Windows Security Events via Azure Monitor Agent  
**Event IDs:** 4688 (A new process has been created)

**KQL Query Used:**
```kql
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(1h)
| where CommandLine has_any ("whoami", "net user", "net localgroup", "ipconfig", "systeminfo")
| project TimeGenerated, Account, Computer, CommandLine, NewProcessName
```

**Query Results:**

| Time | Account | Process | Command |
|---|---|---|---|
| 22:52:30.734 | sentinel-win-vm\labadmin | C:\Windows\System32\systeminfo.exe | systeminfo |
| 22:52:30.671 | sentinel-win-vm\labadmin | C:\Windows\System32\ipconfig.exe | ipconfig /all |
| 22:52:30.560 | sentinel-win-vm\labadmin | C:\Windows\System32\whoami.exe | whoami |

---

## Investigation

### Affected Assets
- **Host:** sentinel-win-vm (Azure VM, West US 2)
- **Acting Account:** sentinel-win-vm\labadmin
- **Processes Executed:** whoami.exe, ipconfig.exe, systeminfo.exe, net.exe

### Analysis
At 22:52:30 UTC, a cluster of reconnaissance commands was executed on `sentinel-win-vm` within a sub-second window. The simultaneous execution of `whoami`, `ipconfig /all`, `systeminfo`, `net user`, and `net localgroup administrators` is consistent with an attacker or post-exploitation framework performing automated host enumeration immediately after gaining access.

The commands collected the following information:
- **whoami:** Current user context (`sentinel-win-vm\labadmin`) and privileges
- **net user:** All local user accounts including `backdooruser`, `labadmin`, `DefaultAccount`, `Guest`, `WDAGUtilityAccount`
- **net localgroup administrators:** Confirmed `backdooruser` and `labadmin` as local administrators
- **ipconfig /all:** Full network configuration including IPv4 (10.0.0.4), DNS servers, DHCP configuration
- **systeminfo:** OS version, patch level, hardware details, domain membership (WORKGROUP)

This data collectively provides an attacker with sufficient information to plan lateral movement, identify unpatched vulnerabilities, and understand the network topology.

The sub-second execution window strongly suggests these commands were run as part of a script rather than manually typed, which is characteristic of post-exploitation frameworks such as Cobalt Strike, Metasploit, or custom PowerShell scripts.

### Findings
- Five reconnaissance commands executed within a single second — scripted execution confirmed
- Full host enumeration completed: users, groups, network, OS details
- `backdooruser` confirmed as Administrator via `net localgroup` output
- No evidence of data exfiltration following reconnaissance
- No C2 network connections detected in the incident window

---

## Response Actions

| Action | Status |
|---|---|
| Identified all processes executed in the incident window | Complete |
| Reviewed network connections from host post-reconnaissance | Complete |
| Confirmed no outbound connections to suspicious IPs | Complete |
| Correlated with IR-002 and IR-003 — same session | Complete |
| Incident marked as simulated lab activity | Complete |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|---|---|---|---|
| Discovery | T1082 | — | System Information Discovery via systeminfo.exe and ipconfig.exe |
| Discovery | T1033 | — | System Owner/User Discovery via whoami.exe |
| Discovery | T1087 | T1087.001 - Local Account | Account Discovery via net user and net localgroup |

---

## Recommendations

1. Restrict execution of `net.exe`, `whoami.exe`, and `systeminfo.exe` via AppLocker or WDAC policies for non-administrative users
2. Alert on execution of reconnaissance commands outside of approved maintenance windows
3. Implement script block logging to capture full PowerShell execution context
4. Deploy EDR solution to detect post-exploitation framework signatures
5. Monitor for rapid sequential execution of multiple discovery commands — this is a high-confidence IOC

---

## Lessons Learned

The sub-second execution window of multiple reconnaissance commands is a high-confidence indicator of scripted post-exploitation activity. The current detection rule triggers on individual command names — consider adding a rule that specifically detects rapid sequential execution (3+ discovery commands within 5 seconds from the same process parent) as this would reduce false positives from legitimate administrative activity while catching automated enumeration.
