# Potential Spearphishing Attachment Execution

## Goal
Identify Office applications spawning script interpreters or LOLBins shortly after opening files from user download, temp, or cache paths.

## Why This Alert Matters
Malicious attachments remain one of the most common initial-access mechanisms. Office applications that launch PowerShell, CMD, MSHTA, WScript, CScript, or Rundll32 shortly after opening a file from Downloads, Temp, or Internet cache paths may indicate malicious macros, embedded scripts, or user execution of a weaponized attachment. This guide is based on a rule that correlates Office parent processes, suspicious child interpreters, and download or cache execution context. :contentReference[oaicite:15]{index=15}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- the parent process is an Office application such as:
  - `winword.exe`
  - `excel.exe`
  - `powerpnt.exe`
  - `outlook.exe`
- the child process is one of:
  - `powershell.exe`
  - `cmd.exe`
  - `mshta.exe`
  - `wscript.exe`
  - `cscript.exe`
  - `rundll32.exe`
- the Office file originated from:
  - `Downloads`
  - `AppData\Local\Temp`
  - `INetCache` :contentReference[oaicite:16]{index=16}

## Likely ATT&CK Mapping
- **T1566.001** – Phishing: Spearphishing Attachment

## Initial Triage Questions
1. Which Office application spawned the child process?
2. What document path was involved?
3. Was the file opened from Downloads, Temp, or browser cache?
4. What child process and command line were launched?
5. Did the document arrive by email, Teams, or another delivery method?
6. Were macros, external templates, or embedded scripts involved?
7. Did the execution lead to persistence, credential access, or staging?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessFolderPath`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessCommandLine`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Review the parent Office process
- Identify which Office application opened the file.
- Determine whether the document was:
  - downloaded recently
  - opened from email attachment context
  - extracted from an archive
  - opened from a temp or cached path

### 2. Inspect the child process
- Review whether the child process is:
  - PowerShell
  - CMD
  - MSHTA
  - script host
  - Rundll32
- Inspect the command line for download, execution, or obfuscation behavior.

### 3. Trace delivery context
- Identify how the file arrived:
  - email attachment
  - Teams/shared file
  - browser download
  - removable media
- Review sender, source, and lure context if available.

### 4. Correlate with follow-on activity
Look for:
- outbound network traffic
- encoded PowerShell
- persistence creation
- Defender tampering
- archive staging
- credential dumping or browser credential access

### 5. Validate legitimate macro or automation workflows
- Confirm whether the document is part of:
  - approved internal automation
  - macro-enabled business processes
  - lab or security simulation testing
- If not, treat the event as high value.

## Common Benign Explanations
- Approved macro-enabled business workflows
- Internal automation launched through Office
- Security testing with malicious-document simulations :contentReference[oaicite:17]{index=17}

## Escalate When
Escalate if:
- the attachment came from an untrusted source
- the document launched a script interpreter or LOLBin
- the child process downloads, stages, or executes additional content
- the host shows persistence, credential access, or outbound transfer afterward
- the user did not expect the attachment or action

## Suggested Response Actions
- Preserve the document, process tree, and command-line evidence
- Quarantine or analyze the attachment safely
- Review related email, chat, or download telemetry
- Isolate the endpoint if malicious execution is confirmed
- Search for the same document hash, filename, or process chain across the environment
- Coordinate with messaging and IR teams for campaign response

## Analyst Notes
This is a strong initial-access and execution analytic because it ties likely user-opened Office content directly to suspicious child-process launch. The delivery path and child command line are the key triage factors.