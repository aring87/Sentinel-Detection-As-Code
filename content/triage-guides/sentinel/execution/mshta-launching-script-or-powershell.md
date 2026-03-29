# MSHTA Launching Script or PowerShell

## Goal
Identify suspicious MSHTA execution associated with script launch, PowerShell invocation, or remote content retrieval.

## Why This Alert Matters
`mshta.exe` is a well-known LOLBin frequently abused to proxy execution, retrieve remote content, or launch scripting engines while blending into native Windows activity. Even in environments where HTA use is rare, MSHTA may still appear during malware staging, fileless execution, or initial payload launch. This guide is based on a detection that looks for MSHTA command lines containing script, PowerShell, or remote content indicators. :contentReference[oaicite:13]{index=13}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- `FileName =~ "mshta.exe"`

and the command line contains indicators such as:
- `vbscript:`
- `javascript:`
- `http://`
- `https://`
- `powershell`
- `cmd.exe`
- `wscript`
- `cscript` :contentReference[oaicite:14]{index=14}

## Likely ATT&CK Mapping
- **T1218.005** – System Binary Proxy Execution: Mshta
- **T1059** – Command and Scripting Interpreter

## Initial Triage Questions
1. Was MSHTA used to fetch remote content or run inline script?
2. Did the command reference PowerShell, CMD, or another script interpreter?
3. Was the process launched from a suspicious parent or user-writable path?
4. Does the host normally use HTA-based applications?
5. Was there follow-on persistence, download, or outbound traffic?
6. Is there evidence of browser lure, phishing, or user interaction beforehand?
7. Was the HTA content local, inline, or remote?

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

### 1. Determine how MSHTA was used
- Review whether the command line references:
  - inline `vbscript:` or `javascript:`
  - remote URL
  - local HTA file
  - PowerShell or CMD invocation
- Decide whether MSHTA is acting as the initial execution vehicle or as a proxy launcher.

### 2. Review parent process and launch path
- Check whether the parent process is:
  - browser
  - Explorer
  - Office application
  - script interpreter
  - another LOLBin
- Determine whether the HTA or launched content came from a writable path.

### 3. Check for follow-on execution
Look for:
- PowerShell or CMD child processes
- file downloads
- script writes
- persistence creation
- Defender tampering
- network connections after MSHTA starts

### 4. Validate legitimate HTA usage
- Confirm whether the environment still uses legacy HTA applications.
- Check whether the path, signer, or application name matches approved internal software.
- If HTA use is generally rare in the environment, suspicion should increase.

### 5. Review adjacent user or lure activity
- Check for:
  - email attachment execution
  - browser lures
  - OAuth lure activity
  - paste-and-run execution
  - fake CAPTCHA workflows

## Common Benign Explanations
- Rare legacy HTA-based administration tools
- Internal legacy applications using HTA components :contentReference[oaicite:15]{index=15}

## Escalate When
Escalate if:
- MSHTA retrieves remote content
- the command launches PowerShell, CMD, or another interpreter
- the process is parented by browser, Office, or another suspicious chain
- the content originates from a writable or downloaded location
- the host does not normally use HTA-based applications

## Suggested Response Actions
- Preserve the full MSHTA command line and parent process chain
- Collect referenced HTA, script, or remote content if possible
- Search for the same URL, inline script, or command pattern elsewhere
- Isolate the host if MSHTA led to malicious execution
- Review neighboring persistence and network events

## Analyst Notes
MSHTA is often high-signal in modern environments because legitimate use is increasingly rare. It is especially important when combined with remote URLs, inline script, or interpreter launch behavior.