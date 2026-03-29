# PowerShell Encoded Command from Temp or User-Writable Path

## Goal
Identify encoded PowerShell execution tied to temp or user-writable locations, which may indicate downloaded or staged payload execution.

## Why This Alert Matters
Encoded PowerShell is already suspicious in many environments, but it becomes even more concerning when the PowerShell binary, parent process, or launch context is tied to writable locations such as `Temp`, `Downloads`, `AppData`, or `Users\Public`. That pattern can indicate recently downloaded scripts, staged malware, or user-driven execution of malicious content. This guide is based on a rule that detects `-enc` or `-encodedcommand` together with writable-path execution context. :contentReference[oaicite:22]{index=22}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- `FileName` is `powershell.exe` or `pwsh.exe`
- the command line contains `-enc` or `-encodedcommand`
- the PowerShell process path or parent process folder path contains:
  - `\Temp\`
  - `\AppData\Local\`
  - `\AppData\Roaming\`
  - `\Users\Public\`
  - `\Downloads\`

It also attempts to decode the encoded payload for analysis. :contentReference[oaicite:23]{index=23}

## Likely ATT&CK Mapping
- **T1059.001** – Command and Scripting Interpreter: PowerShell

## Initial Triage Questions
1. Which writable path was involved: process path, parent path, or both?
2. What does the decoded command do?
3. Did the payload originate from a recent download or dropped file?
4. Which parent process launched PowerShell?
5. Is there a recently created file in the same path?
6. Was the execution user-driven, scripted, or service-driven?
7. Did the activity lead to persistence, outbound connections, or credential access?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FolderPath`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessFolderPath`
- `InitiatingProcessCommandLine`
- `Encoded`
- `Decoded`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Review the writable-path context
- Determine whether the suspicious context came from:
  - the PowerShell executable path
  - the parent process path
  - a recent file in the same folder
- Confirm whether the location is truly user-writable or transient.

### 2. Decode the payload
- Review the decoded content for:
  - downloads
  - process launch
  - registry writes
  - persistence logic
  - credential theft
  - anti-defense behavior
- Treat layered or nested encoding as especially suspicious.

### 3. Trace file origin
- Check whether the payload was launched from:
  - browser download
  - archive extraction
  - dropped file in AppData or Temp
  - copied file from network share
- Review nearby file creation and modification events.

### 4. Correlate with post-execution behavior
Look for:
- network connections
- scheduled tasks
- Run key changes
- service creation
- Defender tampering
- browser credential access
- archive creation or exfiltration

### 5. Validate any benign explanation
- Determine whether the host is used for:
  - development
  - packaging
  - lab testing
  - admin scripting from temporary folders
- This should be uncommon on most standard endpoints.

## Common Benign Explanations
- Rare internal admin scripts launched from downloads or temp locations
- Developer testing from unpacked or transient working folders :contentReference[oaicite:24]{index=24}

## Escalate When
Escalate if:
- the decoded payload is malicious or suspicious
- the launch context is from Temp, Downloads, AppData, or Users\Public
- the parent process is browser, Explorer, Office, or another user-driven chain
- there is follow-on persistence or network activity
- the file appears newly downloaded or staged

## Suggested Response Actions
- Preserve the encoded and decoded content
- Collect nearby file artifacts from the writable path
- Review user interaction and download history
- Isolate the host if malicious staged execution is confirmed
- Search for the same path, payload, or hash elsewhere in the environment
- Tune carefully, because writable-path encoded PowerShell should usually remain high interest

## Analyst Notes
This is a narrower, higher-confidence companion to general encoded PowerShell detection. The writable-path context often makes the difference between suspicious automation and likely malicious staging.