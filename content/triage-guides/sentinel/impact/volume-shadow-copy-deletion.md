# Volume Shadow Copy Deletion

## Goal
Identify attempts to delete Windows volume shadow copies, which are commonly removed by ransomware and destructive malware to prevent recovery.

## Why This Alert Matters
Shadow copies provide a recovery path for files and system state. Attackers often delete them before encryption or other destructive activity to make restoration harder and increase operational impact.

## What the Detection Is Looking For
This detection looks for process execution involving built-in Windows utilities commonly used to remove shadow copies, including:
- `vssadmin.exe`
- `wmic.exe`
- `powershell.exe`

It specifically looks for command-line indicators such as:
- `delete shadows`
- `shadowcopy delete`
- `Win32_Shadowcopy`

## Likely ATT&CK Mapping
- T1490 – Inhibit System Recovery

## Initial Triage Questions
1. Was the shadow copy deletion authorized?
2. What process and parent process initiated the action?
3. Was the activity performed by an admin, backup operator, or unexpected user?
4. Did mass file changes, ransom-note activity, or boot/recovery tampering happen nearby?
5. Is this host a server, workstation, backup system, or test/lab machine?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the command
- Confirm which utility was used.
- Review the full command line for deletion intent.
- Determine whether the command was interactive, scripted, or launched by another process.

### 2. Identify the initiator
- Review the account context.
- Review the parent and grandparent process chain.
- Look for suspicious launchers such as:
  - `cmd.exe`
  - `powershell.exe`
  - scheduled tasks
  - remote execution tools
  - Office or script engines

### 3. Check for adjacent ransomware indicators
Review the same device and timeframe for:
- mass file rename or encryption behavior
- ransom note creation
- event log clearing
- boot configuration tampering
- security tool disable attempts
- unusual outbound network activity

### 4. Validate business context
- Determine whether the host runs approved backup, restore, imaging, or lab validation workflows.
- Check for change tickets or maintenance records.
- Confirm whether the account normally performs recovery-related administration.

### 5. Assess severity
- If shadow copy deletion appears unauthorized, treat it as high priority.
- Increase urgency if paired with encryption or destructive changes on the same host.

## Common Benign Explanations
- Approved backup maintenance
- Restore or recovery workflow testing
- Lab validation
- Imaging or system repair activity

## Escalate When
Escalate if:
- the user or admin cannot explain the deletion
- the command was launched by suspicious scripting or remote tools
- encryption-like file activity is also present
- the endpoint shows multiple impact or defense-evasion signals
- the account context is unusual for recovery administration

## Suggested Response Actions
- isolate the host if destructive activity is ongoing
- preserve process tree and command-line evidence
- check recent file modifications and ransom note indicators
- review other impacted systems for the same command pattern
- notify incident response and recovery stakeholders

## Analyst Notes
This should be your main shadow-copy-deletion guide. It is broader and stronger than a `vssadmin.exe`-only analytic because it also covers `wmic.exe` and PowerShell-based deletion paths.