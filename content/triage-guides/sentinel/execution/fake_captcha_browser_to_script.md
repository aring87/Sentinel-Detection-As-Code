# Suspicious Fake CAPTCHA Browser-to-Script Execution Chain

## Goal
Identify likely fake CAPTCHA or browser-lure activity followed by script interpreter or LOLBin execution from a browser context.

## Why This Alert Matters
Fake CAPTCHA lures and similar browser-based social engineering techniques are increasingly used to trick users into launching commands or payloads locally. Rather than dropping obvious malware first, the attacker convinces the user to trigger PowerShell, CMD, MSHTA, Rundll32, or another native interpreter directly from a browser-driven workflow. This can provide an initial foothold while blending into user activity. This guide is based on a detection that correlates browser parent processes with child script interpreters or LOLBins and looks for download, decode, and remote-execution indicators in the child command line. :contentReference[oaicite:7]{index=7}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where a browser process such as:
- `chrome.exe`
- `msedge.exe`
- `firefox.exe`
- `brave.exe`
- `iexplore.exe`

spawns a child process such as:
- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`
- `rundll32.exe`
- `regsvr32.exe`

It then looks for suspicious indicators in the child command line, including:
- `frombase64string`
- `invoke-expression`
- `iwr`
- `irm`
- `curl`
- `wget`
- `bitsadmin`
- `javascript:`
- `http://`
- `https://` :contentReference[oaicite:8]{index=8}

## Likely ATT&CK Mapping
- **T1204.001** – User Execution: Malicious Link
- **T1059.001** – PowerShell
- **T1059.003** – Windows Command Shell

## Initial Triage Questions
1. Which browser launched the child process?
2. What was the user doing in the browser immediately beforehand?
3. Which interpreter or LOLBin was spawned?
4. Does the command line contain download, decode, or remote execution behavior?
5. Did the payload execute from a writable or recently downloaded path?
6. Was the user interacting with a CAPTCHA, software prompt, document lure, or fake update page?
7. Did the same device later show persistence, credential access, or outbound network traffic?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `FileName`
- `ProcessCommandLine`
- `SHA1`
- `SHA256`
- `ReportId`

## Investigation Steps

### 1. Review the browser execution chain
- Confirm which browser initiated the child process.
- Determine whether the browser command line or browsing context suggests:
  - a fake CAPTCHA page
  - a download prompt
  - a lure page
  - a malicious redirect
- Prioritize cases where the child process launched immediately after user browsing activity.

### 2. Inspect the child process
- Review the child binary and full command line.
- Determine whether the command is:
  - downloading content
  - decoding a payload
  - executing script directly
  - using native utilities for staging
- Pay close attention to encoded or obfuscated strings.

### 3. Check writable-path and download context
- Investigate whether the execution chain involved:
  - `Downloads`
  - `Temp`
  - `AppData`
  - `Users\Public`
  - `ProgramData`
- Review nearby file creation or modification events.

### 4. Correlate with follow-on activity
Look for:
- PowerShell encoded command execution
- suspicious web download via Certutil or Bitsadmin
- persistence creation
- Defender tampering
- archive creation
- outbound network traffic
- browser credential store access

### 5. Validate user intent
- Confirm whether the user knowingly launched the command.
- Ask whether they were told to:
  - paste a command
  - click a verification prompt
  - install a browser component
  - fix a browser or security issue
- Social-engineering indicators significantly raise confidence.

## Common Benign Explanations
- Administrator testing from a browser
- Internal web portals intentionally launching local tools
- Developer workflows that trigger scripts from browser-delivered content :contentReference[oaicite:9]{index=9}

## Escalate When
Escalate if:
- the user was lured into running a command
- the child process performs download, decoding, or remote execution
- the payload came from a writable or downloaded location
- the device later shows persistence, credential access, or C2
- the browser interaction aligns with fake CAPTCHA or scam behavior

## Suggested Response Actions
- Preserve the process tree and command-line telemetry
- Review browser history, URL telemetry, and download artifacts
- Quarantine downloaded payloads if present
- Isolate the endpoint if malicious execution is confirmed
- Search for the same parent-child chain across the environment
- Review other users who may have visited the same lure

## Analyst Notes
This is a strong user-execution analytic because it links browser activity directly to interpreter or LOLBin launch. It is especially valuable when correlated with suspicious URLs, downloads, or user-reported fake CAPTCHA prompts.