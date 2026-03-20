# WMI Remote Process Execution

## Goal
Identify WMIC or PowerShell-based WMI calls used to spawn processes on remote systems.

## Why This Alert Matters
WMI is a common dual-use technology for remote administration, but it is also widely used by attackers for lateral movement and remote code execution. Remote WMI execution can allow an adversary to launch commands on other hosts without dropping obvious tooling.

## What the Detection Is Looking For
This detection looks for:
- `wmic.exe`
- `powershell.exe`

with command-line indicators such as:
- `process call create`
- `Invoke-WmiMethod`
- `Win32_Process`
- `-ComputerName`

## Likely ATT&CK Mapping
- T1047 – Windows Management Instrumentation

## Initial Triage Questions
1. What remote host was targeted?
2. What command or process was created remotely?
3. Is WMI-based remote management normal for this account or team?
4. Was there remote logon, share access, or file transfer activity nearby?
5. Did the remote execution lead to follow-on activity on the target system?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the WMI activity
- Confirm whether `wmic.exe` or PowerShell initiated the command.
- Review the full command line for:
  - target host
  - namespace or class references
  - remote process creation syntax
  - payload command or executable

### 2. Identify the target and payload
- Determine which host was targeted.
- Identify the command created remotely.
- Assess whether the payload is administrative, suspicious, or clearly malicious.

### 3. Review initiator context
- Determine whether the account normally performs WMI administration.
- Review parent processes and whether the command came from a script, batch file, or remote tool.
- Check whether the same account has recent suspicious sign-ins or privilege use.

### 4. Correlate with other lateral movement activity
Search for:
- remote scheduled tasks
- remote service creation
- admin share access
- file copy activity
- credential theft indicators
- process launches on the target endpoint

### 5. Assess destination host impact
- Review child process execution on the remote host if available.
- Check whether the command created persistence, staged tools, or launched reconnaissance or dumping utilities.
- Determine whether additional hosts were targeted in sequence.

## Common Benign Explanations
- Systems management and admin automation
- Remote inventory tools
- Patch management
- Scripted health checks

## Escalate When
Escalate if:
- the account does not normally use WMI for administration
- the payload is suspicious or untrusted
- the target is sensitive or unexpected
- multiple hosts are targeted
- WMI execution correlates with credential abuse or file copy activity

## Suggested Response Actions
- preserve the full command line and process tree
- identify the target host and remotely executed command
- review destination host telemetry for resulting processes
- search for the same WMI pattern across the environment
- notify IR if malicious lateral movement is suspected

## Analyst Notes
This is the primary WMI lateral movement guide. It is broader and better normalized than the older version because it explicitly includes both WMIC syntax and PowerShell WMI methods used to create remote processes.