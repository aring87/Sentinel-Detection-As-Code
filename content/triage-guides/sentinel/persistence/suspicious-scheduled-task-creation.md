# Suspicious Scheduled Task Creation

## Goal
Identify creation of scheduled tasks that may be used to establish persistence on a Windows host.

## Why This Alert Matters
Scheduled tasks are one of the most common persistence mechanisms because they are easy to create, blend into normal administration, and can run code on logon, startup, or on a time-based trigger. The standardized rule covers both `schtasks.exe` and Task Scheduler PowerShell methods, making it the best primary guide.

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `schtasks.exe`
- `powershell.exe`

with command-line patterns such as:
- `/create`
- `Register-ScheduledTask`
- `New-ScheduledTask`

## Likely ATT&CK Mapping
- T1053.005 – Scheduled Task

## Initial Triage Questions
1. What task was created, and what action does it run?
2. Which user or process created the task?
3. Is the task trigger consistent with legitimate admin activity?
4. Does the task launch a trusted binary, or something in a suspicious path?
5. Is there related persistence, execution, or lateral movement activity nearby?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine
- InitiatingProcessFileName

## Investigation Steps
### 1. Validate the task creation event
- Confirm whether the task was created with `schtasks.exe` or PowerShell.
- Review the full command line for:
  - task name
  - trigger
  - action/command
  - run-as context
  - hidden or stealthy flags

### 2. Identify the task payload
- Determine what executable, script, or LOLBin the task launches.
- Check whether the payload path points to:
  - `AppData`
  - `Temp`
  - `ProgramData`
  - user profile folders
  - network paths or admin shares

### 3. Review the initiating context
- Identify the creating account.
- Determine whether the initiating process is expected to manage tasks.
- Review parent process lineage for suspicious launch chains.

### 4. Correlate with nearby suspicious behavior
Look for:
- Run key modification
- service creation or service hijack
- dropped payloads
- PowerShell execution
- remote scheduled task creation or lateral movement patterns

### 5. Inspect the created task on the endpoint
- Review the actual task registration details if available.
- Determine whether the trigger is:
  - at logon
  - at startup
  - on idle
  - time-based
  - event-triggered
- Evaluate whether the task was created for persistence, execution, or maintenance.

## Common Benign Explanations
- Legitimate enterprise task deployment
- Admin automation and maintenance jobs
- IT troubleshooting or scheduled operations

## Escalate When
Escalate if:
- the task launches a suspicious or newly dropped payload
- the creator is not expected to manage scheduled tasks
- the command is heavily obfuscated or stealthy
- the same host shows other persistence mechanisms
- the task appears across multiple systems unexpectedly

## Suggested Response Actions
- preserve the command line and task metadata
- capture the referenced payload
- disable or remove the task if confirmed malicious
- review child process execution from the task
- hunt for the same task name or payload across the environment

## Analyst Notes
Use this as the primary scheduled task persistence guide. It is stronger than the older version because it includes `New-ScheduledTask` in addition to `Register-ScheduledTask` and `schtasks /create`, and it explicitly encourages review of follow-on persistence or lateral movement activity.