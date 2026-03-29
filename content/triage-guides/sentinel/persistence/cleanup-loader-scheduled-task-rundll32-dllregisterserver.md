# CleanUpLoader Scheduled Task Rundll32 DLLRegisterServer

## Goal
Identify scheduled task creation that launches `rundll32.exe` with `DllRegisterServer` against DLLs in suspicious `AppData\Roaming` paths, a pattern associated with CleanUpLoader-style persistence.

## Why This Alert Matters
Some malware families and loader chains establish persistence by creating scheduled tasks that invoke `rundll32.exe` against DLLs dropped into user-profile paths, especially under `AppData\Roaming`. When that DLL path looks random or newly created, the behavior can indicate masquerading, user-profile staging, and persistence that blends in with normal Windows components. This guide is based on a rule that detects `schtasks.exe` creating a task whose action includes both `rundll32` and `DllRegisterServer` with an `AppData\Roaming` path. :contentReference[oaicite:8]{index=8}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- `FileName =~ "schtasks.exe"`
- the command line contains `/Create`
- the command line contains both:
  - `rundll32`
  - `DllRegisterServer`
- the command line references `\AppData\Roaming\`

It surfaces the device, creating account, task creation command, parent process, and file hash context. :contentReference[oaicite:9]{index=9}

## Likely ATT&CK Mapping
- **T1053.005** – Scheduled Task/Job: Scheduled Task
- **T1218.011** – System Binary Proxy Execution: Rundll32

## Initial Triage Questions
1. What scheduled task name, trigger, and action were created?
2. What exact DLL path was referenced under `AppData\Roaming`?
3. Does the folder name look random, newly created, or masqueraded?
4. Is the task name attempting to resemble a Windows component or updater?
5. What process created the task?
6. Did the DLL arrive through a suspicious download or installer?
7. Was there follow-on network, loader, or persistence behavior?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `InitiatingProcessAccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Review the scheduled task command
- Extract the task name, trigger, and full action.
- Confirm whether the action launches `rundll32.exe` with `DllRegisterServer`.
- Note whether the task is set to run:
  - at logon
  - on a timer
  - once then persist
  - as a specific user or with elevated privileges

### 2. Inspect the DLL path
- Review the referenced DLL location under `AppData\Roaming`.
- Determine whether:
  - the folder name is random-looking
  - the DLL was recently dropped
  - the DLL name masquerades as a legitimate component
- Check whether the DLL is signed or known-good.

### 3. Trace the origin of the DLL
Look for:
- recent downloads
- archive extraction
- fake installer activity
- freeware or utility masquerading
- parent processes like browser, Explorer, or suspicious setup binaries

### 4. Review associated malware or loader indicators
- Check for:
  - network beacons
  - follow-on DLL registration
  - additional scheduled tasks
  - Run key persistence
  - Defender tampering
  - LOLBin execution chains

### 5. Validate benign explanation
- Very rarely, legitimate software may register DLLs from user-profile paths.
- Confirm whether the software package is approved and whether the task aligns with known updater behavior.

## Common Benign Explanations
- Rare legitimate software registration activity using Rundll32 from user-profile paths
- Edge-case installer or updater activity in roaming profile folders :contentReference[oaicite:10]{index=10}

## Escalate When
Escalate if:
- the DLL path is random, user-writable, or newly created
- the task name masquerades as a Windows or security component
- the creating process is suspicious or user-driven
- there are related downloader, loader, or beaconing indicators
- the device is not expected to create DLL-registration tasks from roaming paths

## Suggested Response Actions
- Preserve the full task-creation command and process ancestry
- Collect the DLL for analysis if safe to do so
- Review the scheduled task directly on the host
- Search for the same DLL path, task name, or hash across the environment
- Isolate the endpoint if malicious loader behavior is confirmed
- Investigate related downloads or fake software installs

## Analyst Notes
This is a high-value specialized persistence analytic. The strongest signals are the roaming-path DLL, the Rundll32 registration pattern, and a task name or folder structure that looks random or masqueraded.