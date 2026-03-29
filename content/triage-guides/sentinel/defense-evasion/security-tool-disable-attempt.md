# Security Tool Disable Attempt

## Goal
Identify attempts to stop security services or alter Windows Defender settings and exclusions in order to reduce host protections.

## Why This Alert Matters
Attackers frequently try to impair or disable endpoint security controls before executing payloads, dumping credentials, or establishing persistence. Changes to Defender settings, exclusions, or core security service states can significantly reduce detection coverage and enable follow-on malicious activity.

This detection focuses on process creation involving common tooling used to alter security settings or stop security services. :contentReference[oaicite:7]{index=7}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for commands involving:
- `powershell.exe`
- `cmd.exe`
- `sc.exe`
- `net.exe`
- `reg.exe`

It looks for command-line patterns such as:
- `Set-MpPreference`
- `DisableRealtimeMonitoring`
- `Add-MpPreference`
- `stop`
- `config`
- `WinDefend`
- `Sense`

The goal is to surface attempts to stop services or modify Windows Defender behavior and exclusions. :contentReference[oaicite:8]{index=8}

## Likely ATT&CK Mapping
- **T1562.001** – Impair Defenses: Disable or Modify Tools

## Initial Triage Questions
1. Which security control was targeted?
2. Was the activity aimed at Defender settings, exclusions, or service state?
3. Which process and account executed the command?
4. Was the activity part of approved maintenance or troubleshooting?
5. Did the change affect real-time monitoring, behavior monitoring, or service availability?
6. Was malicious execution, staging, or persistence observed nearby?
7. Did the same actor also change logging or recovery settings?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`

## Investigation Steps

### 1. Identify the targeted control
- Review whether the command targeted:
  - Windows Defender preferences
  - service stop actions
  - service reconfiguration
  - exclusion additions
  - sensor or security platform processes
- Determine whether the target was:
  - `WinDefend`
  - `Sense`
  - another core security component

### 2. Review the initiating process and user
- Check whether the command was launched by:
  - PowerShell
  - CMD
  - `sc.exe`
  - `net.exe`
  - `reg.exe`
- Validate whether the user is an approved security or systems administrator.

### 3. Determine what changed
- Look for:
  - monitoring disabled
  - exclusions added
  - service stop attempts
  - startup type changes
  - sensor or EDR disablement
- Assess whether the change succeeded if you have follow-on telemetry.

### 4. Correlate with nearby malicious behavior
Look for:
- malware execution
- suspicious downloads
- encoded PowerShell
- persistence creation
- credential dumping
- event log clearing
- PowerShell logging disablement

### 5. Validate benign context
- Confirm whether the event aligns with:
  - maintenance windows
  - approved Defender policy changes
  - lab testing
  - troubleshooting by security staff
- If not, escalate quickly.

## Common Benign Explanations
- Planned security maintenance
- Approved Defender policy changes by security administrators
- Lab validation or controlled testing

These align directly with the rule’s false-positive guidance. :contentReference[oaicite:9]{index=9}

## Escalate When
Escalate if:
- monitoring or security services were disabled unexpectedly
- exclusions were added for suspicious paths or file types
- the actor is not authorized to modify endpoint protections
- the host shows malware, persistence, or credential-access behavior nearby
- the same user also cleared logs or disabled PowerShell logging

## Suggested Response Actions
- Preserve process and configuration-change evidence
- Verify whether the attempted change succeeded
- Re-enable protections if the modification is unauthorized
- Review the host for malicious payloads or persistence
- Search for the same command patterns elsewhere in the environment
- Contain the host if active compromise is confirmed

## Analyst Notes
This is a high-value defense-evasion analytic because security-tool tampering often happens early in an intrusion or immediately before more damaging actions. It is especially important when paired with suspicious downloads, encoded PowerShell, credential access, or recovery tampering.