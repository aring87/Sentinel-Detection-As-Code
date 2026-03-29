# Suspicious Scheduled Task Creation

## Goal
Identify scheduled task creation via `schtasks` or Task Scheduler PowerShell commands that may establish persistence.

## Why This Alert Matters
Scheduled tasks are widely used for benign administration, software maintenance, and updater logic, but they are also one of the most common persistence techniques on Windows. Attackers may use `schtasks.exe`, `Register-ScheduledTask`, or `New-ScheduledTask` to run payloads at logon, startup, or on a timer. This guide is based on a rule that detects scheduled-task creation across both `schtasks` and PowerShell-based task registration patterns. :contentReference[oaicite:29]{index=29}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- `FileName` is:
  - `schtasks.exe`
  - `powershell.exe`
  - `pwsh.exe`
- the command line contains:
  - `/create`
  - `Register-ScheduledTask`
  - `New-ScheduledTask`

It surfaces the device, user, process, command line, parent process, and hash context. :contentReference[oaicite:30]{index=30}

## Likely ATT&CK Mapping
- **T1053.005** – Scheduled Task/Job: Scheduled Task

## Initial Triage Questions
1. What task name, trigger, and action were created?
2. Was the task created via `schtasks` or PowerShell?
3. Does the task launch a script, LOLBin, or binary from a writable path?
4. Is the creating user or process expected to manage tasks on this host?
5. Was the task part of software installation, updater logic, or admin automation?
6. Were there nearby downloads, DLL drops, or service/Run key changes?
7. Does the task appear to provide one-time execution or long-term persistence?

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

### 1. Review the task-creation command
- Identify whether the task was created through:
  - `schtasks.exe`
  - `Register-ScheduledTask`
  - `New-ScheduledTask`
- Extract the task name, trigger, action, and run context.

### 2. Inspect the task action
- Determine whether the task launches:
  - PowerShell
  - CMD
  - script hosts
  - Rundll32
  - a custom binary
- Review whether the payload path points to:
  - `AppData`
  - `Temp`
  - `Users\Public`
  - `ProgramData`
  - download locations

### 3. Review parent process and user context
- Confirm whether the creating process was:
  - installer or updater
  - admin tooling
  - browser or Explorer
  - suspicious script or LOLBin
- The parent process often explains whether the task is benign or malicious.

### 4. Correlate with adjacent persistence or loader behavior
Look for:
- DLL drops
- fake installer activity
- Run key changes
- service configuration
- Defender tampering
- network beaconing
- archive or staging activity

### 5. Validate benign admin or software context
- Scheduled tasks are common in enterprise software and admin workflows.
- Confirm whether the task aligns with:
  - maintenance jobs
  - updater tasks
  - approved automation
  - enterprise deployment

## Common Benign Explanations
- Legitimate enterprise task deployment
- Admin automation and maintenance jobs
- Software installation or updater tasks :contentReference[oaicite:31]{index=31}

## Escalate When
Escalate if:
- the task launches a suspicious script or writable-path binary
- the creating process is user-driven or unknown
- the task name or action appears masqueraded
- there are nearby malware, loader, or other persistence indicators
- the host does not normally receive task-based admin changes

## Suggested Response Actions
- Preserve the full task-creation command and ancestry
- Review the task directly on the endpoint
- Inspect the launched payload path and referenced binaries
- Search for the same task name or action elsewhere
- Remove unauthorized tasks if compromise is confirmed
- Isolate the endpoint if the task is clearly malicious

## Analyst Notes
This is a foundational Windows persistence analytic. The fastest way to triage it is to understand what the task runs, who created it, and whether the payload path is normal for the host.