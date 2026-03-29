# Random AppData Roaming DLL Drop Followed by Scheduled Task

## Goal
Identify DLL creation in suspicious randomly named `AppData\Roaming` folders followed by scheduled task creation, a pattern aligned to CleanUpLoader-style persistence.

## Why This Alert Matters
Dropping DLLs into random-looking `AppData\Roaming` folders and then establishing persistence via scheduled tasks is a common loader and malware technique. It uses user-writable paths, masquerading, and scheduled execution to maintain access while trying to avoid obvious service or startup locations. This guide is based on a rule that correlates DLL creation in random-looking roaming folders with follow-on `schtasks.exe /Create` activity on the same device. :contentReference[oaicite:20]{index=20}

## What the Detection Is Looking For
This detection correlates:
- `DeviceFileEvents` where:
  - a DLL is created or modified
  - the folder path matches a suspicious random-looking `AppData\Roaming` subfolder
- `DeviceProcessEvents` where:
  - `schtasks.exe`
  - `/Create`

The sequence is considered suspicious when task creation follows the DLL drop within a short time window. :contentReference[oaicite:21]{index=21}

## Likely ATT&CK Mapping
- **T1053.005** – Scheduled Task/Job: Scheduled Task
- **T1547** – Boot or Logon Autostart Execution

## Initial Triage Questions
1. What DLL was dropped, and where?
2. Does the folder name appear random or newly created?
3. What process created the DLL?
4. What scheduled task was created afterward?
5. Does the dropped DLL masquerade as a known utility or component?
6. Was there suspicious download or installer activity before the DLL appeared?
7. Did the device show outbound traffic or loader behavior after persistence was established?

## Key Fields To Review
- `DeviceName`
- `DropTime`
- `FolderPath`
- `FileName`
- `InitiatingProcessAccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `TaskTime`
- `TaskProc`
- `TaskCmd`

## Investigation Steps

### 1. Inspect the DLL drop
- Review the full folder path and DLL name.
- Determine whether the subfolder name looks:
  - random
  - newly generated
  - masqueraded as a legitimate application
- Check whether the DLL was signed or known-good.

### 2. Identify the DLL creator
- Review the process that created or modified the DLL.
- Determine whether it was:
  - browser
  - installer
  - archive utility
  - script or LOLBin
  - another suspicious loader

### 3. Review the scheduled task
- Extract the task name, trigger, and action.
- Determine whether the task references the dropped DLL directly or launches a related binary.

### 4. Correlate with follow-on behavior
Look for:
- outbound network connections
- additional DLLs or EXEs in roaming or temp paths
- Rundll32 execution
- Defender tampering
- archive creation or exfiltration
- browser credential or PowerShell activity

### 5. Validate benign software context
- Rare installers may write DLLs to profile paths before task creation.
- Confirm whether the software involved is approved and behaves consistently with known updater logic.

## Common Benign Explanations
- Rare software installers writing DLLs to user-profile subfolders before task creation
- Edge-case roaming-profile software deployments :contentReference[oaicite:22]{index=22}

## Escalate When
Escalate if:
- the folder name is random-looking and not tied to known software
- the DLL creator is suspicious or user-driven
- the task is clearly persistence-oriented
- the device shows follow-on network or loader behavior
- the sequence resembles known CleanUpLoader-style tradecraft

## Suggested Response Actions
- Preserve DLL, task, and process evidence
- Collect the DLL if safe to do so
- Review the task directly on the endpoint
- Search for the same folder pattern, DLL, or task name on other hosts
- Isolate the endpoint if malicious persistence is confirmed
- Review browser/download sources that may have delivered the payload

## Analyst Notes
This is a strong specialized persistence analytic. The combination of random roaming-path DLL drops and scheduled task creation is much more meaningful than either event alone.