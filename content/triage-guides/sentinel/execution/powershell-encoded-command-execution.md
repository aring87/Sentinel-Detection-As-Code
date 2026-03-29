# PowerShell Encoded Command Execution

## Goal
Identify PowerShell execution using encoded commands and review the decoded payload for malicious behavior.

## Why This Alert Matters
Encoded PowerShell is one of the most common execution techniques used to hide malicious commands, evade casual inspection, and deliver script-based payloads. Although there are legitimate administrative uses, encoded commands are often associated with download cradles, credential theft, persistence, defense evasion, and multi-stage post-exploitation activity. This guide is based on a rule that identifies `-enc` or `-encodedcommand` usage and attempts to decode the embedded payload for analyst review. :contentReference[oaicite:19]{index=19}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- `FileName` is `powershell.exe` or `pwsh.exe`
- `ProcessCommandLine` contains `-enc` or `-encodedcommand`

It extracts the Base64 content and attempts to decode it so analysts can review the embedded script or command. :contentReference[oaicite:20]{index=20}

## Likely ATT&CK Mapping
- **T1059.001** – Command and Scripting Interpreter: PowerShell

## Initial Triage Questions
1. What is the decoded PowerShell payload?
2. Does the decoded content perform download, execution, persistence, or credential access?
3. Which parent process launched PowerShell?
4. Was the command executed by a user, script, installer, or service?
5. Did the process run from a normal system context or suspicious path?
6. Was there related network, file, or registry activity nearby?
7. Is the encoded use consistent with approved automation or clearly abnormal?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `Encoded`
- `Decoded`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Decode and review the payload
- Read the decoded content in full.
- Determine whether it contains:
  - download cradles
  - `Invoke-Expression`
  - encoded nested payloads
  - persistence logic
  - registry changes
  - credential theft
  - obfuscation
- If the decoded string is incomplete or unreadable, attempt alternate decoding workflows.

### 2. Review process ancestry
- Identify the parent process and broader execution chain.
- Determine whether PowerShell was launched by:
  - Office
  - browser
  - Explorer
  - scheduled task
  - service
  - remote access tool
- Parent-process context often explains whether this was normal automation or suspicious execution.

### 3. Correlate with related host activity
Look for:
- file creation
- registry modification
- network egress
- security-control tampering
- persistence creation
- archive creation
- child process creation from PowerShell

### 4. Validate administrative context
- Determine whether the host or user normally runs encoded PowerShell for:
  - deployment
  - packaging
  - automation
  - orchestration
- Approved automation should still be checked against baselines.

### 5. Search for the same payload elsewhere
- Search for the same decoded content, hash, or command-line fragment across the environment.
- Repeated reuse often indicates wider compromise or mass deployment.

## Common Benign Explanations
- Approved administrative automation using encoded PowerShell
- Software deployment tooling
- Internal packaging or orchestration frameworks :contentReference[oaicite:21]{index=21}

## Escalate When
Escalate if:
- the decoded payload downloads, executes, persists, or tampers with security controls
- the parent process is suspicious or user-driven
- the command is heavily obfuscated or nested
- the same decoded payload appears on multiple hosts unexpectedly
- the endpoint shows related malicious behavior after execution

## Suggested Response Actions
- Preserve the encoded and decoded payloads
- Capture full process ancestry and related telemetry
- Isolate the host if the payload is malicious
- Search the environment for matching encoded or decoded strings
- Block or detect the specific decoded behavior where practical
- Review whether credentials or persistence were impacted

## Analyst Notes
This is a high-value analytic because it gives the analyst an immediate starting point: the decoded content. The fastest way to triage it is to understand what the decoded payload is doing and what launched it.