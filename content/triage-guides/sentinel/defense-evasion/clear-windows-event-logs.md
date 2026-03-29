# Clear Windows Event Logs

## Goal
Identify commands used to clear Windows event logs in an effort to remove evidence and reduce visibility for defenders.

## Why This Alert Matters
Clearing Windows event logs is a classic defense-evasion technique. Attackers may do this after executing malware, creating persistence, dumping credentials, or moving laterally in order to reduce the available evidence for responders. Even when only a single log is cleared, the action is often high-value because it may indicate the attacker knows they are leaving detectable artifacts.

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `wevtutil.exe`
- `powershell.exe`
- `cmd.exe`

It looks for command-line patterns such as:
- `cl`
- `Clear-EventLog`
- `Remove-EventLog`

The goal is to catch command execution that clears Windows event logs or removes records in a way consistent with anti-forensic activity.

## Likely ATT&CK Mapping
- **T1070.001** – Indicator Removal on Host: Clear Windows Event Logs

## Initial Triage Questions
1. Which account cleared the logs?
2. Which process was used to perform the action?
3. Which logs were targeted?
4. Did the command occur after suspicious execution, persistence, or credential access?
5. Is the host an admin workstation, server, or normal user endpoint?
6. Was the action part of approved maintenance or troubleshooting?
7. Did the same user or host also disable other logging or security controls?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`

## Investigation Steps

### 1. Identify the log-clearing method
- Determine whether the command used:
  - `wevtutil`
  - PowerShell log-clearing cmdlets
  - CMD invoking a log-clearing command
- Extract the exact command line and confirm what was targeted.

### 2. Determine which logs were affected
- Review whether the action targeted:
  - Security logs
  - System logs
  - Application logs
  - PowerShell logs
  - custom or operational logs
- Prioritize clearing of Security and PowerShell-related logs.

### 3. Review preceding activity
Look for suspicious actions immediately before the log clear, such as:
- PowerShell encoded commands
- Defender or logging disablement
- credential dumping
- scheduled task creation
- service creation
- remote access activity
- archive creation or staging

### 4. Validate the actor and context
- Confirm whether the account is an approved administrator.
- Check whether the activity happened during:
  - troubleshooting
  - forensic cleanup
  - lab work
  - approved maintenance
- If not, treat it as high priority.

### 5. Assess follow-on impact
- Determine whether the host continued to show suspicious behavior after logs were cleared.
- Check for:
  - persistence
  - exfiltration
  - malware staging
  - lateral movement

## Common Benign Explanations
- Rare administrator log maintenance
- Lab validation
- Forensic cleanup during controlled testing
- Troubleshooting on nonproduction systems

## Escalate When
Escalate if:
- Security or PowerShell logs were cleared
- the actor is not an approved administrator
- the command follows suspicious execution or persistence activity
- the same host also shows security-control tampering
- the clearing appears selective or timed around other malicious events

## Suggested Response Actions
- Preserve remaining logs and surrounding telemetry immediately
- Review neighboring process, registry, authentication, and file events
- Isolate the host if broader malicious activity is confirmed
- Search for the same account or command pattern across the environment
- Review whether other logging or security controls were modified

## Analyst Notes
This is a high-value anti-forensics alert. Even when it has a benign explanation, event log clearing should be reviewed carefully because it is strongly associated with attacker cleanup and post-compromise concealment.