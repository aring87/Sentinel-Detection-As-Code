# Remote Scheduled Task Creation

## Goal
Identify `schtasks`-based remote task creation that may indicate lateral movement or remote execution.

## Why This Alert Matters
Remote scheduled task creation is a common lateral-movement technique because it allows an attacker to execute commands on another host using built-in Windows functionality. It is frequently used after credential theft or privileged access is obtained, and it can be combined with scripts, LOLBins, or payloads stored on writable paths. This guide is based on a rule that detects `schtasks.exe` commands using both `/create` and `/s`, indicating remote task creation against another system. :contentReference[oaicite:3]{index=3}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `FileName =~ "schtasks.exe"`

and requires the command line to contain:
- `/create`
- `/s`

The rule surfaces the process context, account, command line, parent process, and hash so the analyst can review which remote host and task action were involved. :contentReference[oaicite:4]{index=4}

## Likely ATT&CK Mapping
- **T1053.005** – Scheduled Task/Job: Scheduled Task
- **T1021** – Remote Services

## Initial Triage Questions
1. What remote target was specified with `/s`?
2. What task name, trigger, and action were created?
3. Is the initiating account expected to create remote tasks?
4. Did the task action launch PowerShell, CMD, LOLBins, or a payload from a writable path?
5. Was the activity part of software deployment or orchestration?
6. Are there related remote logons, SMB access, or WMI/service creation events nearby?
7. Is the source device an admin workstation, management host, or normal endpoint?

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

### 1. Review the remote `schtasks` command
- Extract the remote target from the `/s` parameter.
- Identify:
  - task name
  - task action
  - run user
  - trigger or schedule
- Determine whether the task appears designed for one-time execution or persistence.

### 2. Inspect the task action
- Review whether the created task launches:
  - `powershell.exe`
  - `cmd.exe`
  - `mshta.exe`
  - `rundll32.exe`
  - an executable from `Temp`, `AppData`, `Users\Public`, or `ProgramData`
- Suspicious actions increase the likelihood of malicious use.

### 3. Assess the source host and user
- Determine whether the source host is:
  - a legitimate admin or deployment system
  - a jump box
  - a user workstation
  - a newly suspicious endpoint
- Confirm whether the user normally creates tasks remotely.

### 4. Correlate with related remote activity
Look for:
- remote logons
- SMB access
- file copy to admin shares
- WMI remote process execution
- service creation
- credential dumping or privileged logons before the event

### 5. Validate benign orchestration context
- Confirm whether the event aligns with:
  - software deployment
  - patching
  - enterprise job scheduling
  - approved orchestration tooling
- If not, escalate.

## Common Benign Explanations
- Approved administration or orchestration platforms
- Enterprise job scheduling across managed servers
- Software deployment tooling using remote scheduled tasks :contentReference[oaicite:5]{index=5}

## Escalate When
Escalate if:
- the source host is not expected to create remote tasks
- the task action launches script interpreters, LOLBins, or suspicious binaries
- the remote target is high value or unrelated to the user’s role
- there are preceding credential-access or remote logon indicators
- the sequence resembles attacker staging or one-time remote execution

## Suggested Response Actions
- Preserve the full command line and process tree
- Identify the target host and inspect the created task directly
- Review whether the task executed and what it launched
- Search for the same account creating remote tasks on other systems
- Contain the source or target host if malicious execution is confirmed
- Correlate with authentication, SMB, and service-creation logs

## Analyst Notes
This is a strong built-in lateral-movement analytic. It is especially important when a non-management host uses `schtasks /create /s` or when the task action points to suspicious paths or interpreters.