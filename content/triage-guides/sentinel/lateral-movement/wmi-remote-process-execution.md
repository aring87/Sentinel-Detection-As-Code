# WMI Remote Process Execution

## Goal
Identify use of WMIC or PowerShell WMI calls to spawn processes on remote systems.

## Why This Alert Matters
WMI-based remote execution is a common lateral-movement method because it allows attackers to run commands on remote hosts using built-in Windows functionality and valid credentials. It is often used together with credential theft, remote admin shares, or service/task creation. This guide is based on a rule that detects command-line patterns such as `process call create`, `Invoke-WmiMethod`, `Win32_Process`, and `-ComputerName` in `wmic.exe`, `powershell.exe`, or `pwsh.exe`. :contentReference[oaicite:9]{index=9}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `wmic.exe`
- `powershell.exe`
- `pwsh.exe`

It looks for command-line indicators such as:
- `process call create`
- `Invoke-WmiMethod`
- `Win32_Process`
- `-ComputerName`

The goal is to surface likely remote process creation via WMI. :contentReference[oaicite:10]{index=10}

## Likely ATT&CK Mapping
- **T1047** – Windows Management Instrumentation

## Initial Triage Questions
1. What remote host was targeted?
2. What command or payload was executed remotely?
3. Was the activity performed with `wmic` or PowerShell WMI methods?
4. Is the initiating account expected to use WMI for remote execution?
5. Did the same device also show remote logons, SMB copy, or service/task creation?
6. Was the payload a script, LOLBin, or binary from a writable path?
7. Is the source device an admin or management system, or a normal endpoint?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Identify the WMI method used
- Determine whether the execution came from:
  - `wmic process call create`
  - `Invoke-WmiMethod`
  - PowerShell using `Win32_Process`
  - remote PowerShell with `-ComputerName`
- Extract the remote target and payload if visible.

### 2. Review the remote command
- Determine whether the spawned command launched:
  - PowerShell
  - CMD
  - MSHTA
  - Rundll32
  - a custom binary
- Review whether the command line includes URLs, encoded content, or suspicious paths.

### 3. Correlate with other remote activity
Look for:
- remote logons
- admin-share access
- file copy activity
- remote service creation
- remote scheduled task creation
- credential dumping or privileged token abuse আগে the event

### 4. Validate normal admin use
- Confirm whether the host and user normally perform WMI-based administration.
- Common benign use may include:
  - support tooling
  - systems management
  - remote patching
  - inventory operations
- If the host is a user endpoint, suspicion increases.

### 5. Assess execution impact on the target
- If target-host visibility is available, check for:
  - corresponding process creation
  - file writes
  - persistence
  - follow-on network connections
- Determine whether the WMI call was successful and what it launched.

## Common Benign Explanations
- Systems management and admin automation
- Remote inventory or patching activity
- Approved support tooling using WMI for execution :contentReference[oaicite:11]{index=11}

## Escalate When
Escalate if:
- the source host is not expected to use WMI remotely
- the payload is a script interpreter, LOLBin, or suspicious binary
- the command targets a sensitive system
- there is nearby SMB copy, scheduled task creation, or service execution
- the same user also shows credential-access behavior

## Suggested Response Actions
- Preserve the full process command line and ancestry
- Identify the target host and review target-side activity
- Search for the same WMI execution pattern across other hosts
- Validate whether the account is authorized for remote admin activity
- Contain source or target systems if malicious lateral movement is confirmed
- Review related privileged logons and file-transfer activity

## Analyst Notes
This is a strong built-in lateral-movement analytic because WMI remote execution remains heavily used by attackers and defenders alike. The key triage question is whether the source host, user, and remote payload make sense for the environment.