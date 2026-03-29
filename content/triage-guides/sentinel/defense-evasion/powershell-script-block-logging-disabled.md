# PowerShell Script Block Logging Disabled

## Goal
Identify registry changes that disable or weaken PowerShell logging controls such as Script Block Logging or Transcription.

## Why This Alert Matters
PowerShell remains one of the most abused native Windows tools for execution, persistence, and post-exploitation. Logging controls such as Script Block Logging and Transcription are critical for visibility into those actions. When attackers weaken or disable these controls, they reduce the chance that malicious scripts will be captured and analyzed.

This detection is broader than a simple Script Block Logging disable rule because it also considers related policy areas such as Transcription. :contentReference[oaicite:4]{index=4}

## What the Detection Is Looking For
This detection reviews `DeviceRegistryEvents` for registry changes under PowerShell policy paths such as:
- `ScriptBlockLogging`
- `Transcription`

It looks for:
- `RegistryValueSet`
- `RegistryKeyCreated`

The rule is intended to catch changes that disable or weaken PowerShell logging visibility on a host. :contentReference[oaicite:5]{index=5}

## Likely ATT&CK Mapping
- **T1562.001** – Impair Defenses: Disable or Modify Tools

## Initial Triage Questions
1. Which PowerShell logging policy was changed?
2. Was the change tied to Script Block Logging, Transcription, or both?
3. Which process and user made the change?
4. Was the host receiving an expected Group Policy update?
5. Did suspicious PowerShell activity occur before or after the registry modification?
6. Were other security or logging settings also weakened?
7. Is the host a lab, admin, or production system?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `InitiatingProcessAccountName`
- `RegistryKey`
- `RegistryValueName`
- `RegistryValueData`
- `InitiatingProcessFileName`

## Investigation Steps

### 1. Identify the exact policy change
- Confirm whether the modified key is related to:
  - Script Block Logging
  - Script Block Invocation Logging
  - Transcription
- Review whether the value disables, removes, or weakens the setting.

### 2. Review the initiating process
- Determine whether the registry write came from:
  - Group Policy
  - `reg.exe`
  - PowerShell
  - a software installer
  - an unknown executable
- Review the process path and command line where available.

### 3. Correlate with PowerShell activity
Look for:
- encoded PowerShell
- suspicious downloads
- `Invoke-Expression`
- child processes from PowerShell
- LOLBin chaining
- post-change external network traffic

### 4. Validate legitimate change context
- Determine whether the system received a policy update.
- Review CAB records, maintenance windows, or test activity.
- If the host is not expected to change PowerShell policy, treat the event as more suspicious.

### 5. Check for broader evasion behavior
- Search for:
  - event log clearing
  - Defender tampering
  - exclusion additions
  - security tool disablement
  - persistence shortly after the registry change

## Common Benign Explanations
- Group Policy changes from approved admin workflows
- Security testing in a lab
- Legitimate policy reconfiguration or hardening work

These align with the rule’s defined false-positive set. :contentReference[oaicite:6]{index=6}

## Escalate When
Escalate if:
- Script Block Logging or Transcription is disabled unexpectedly
- the initiating process is suspicious or user-driven
- the host is not expected to receive this type of change
- the same host shows encoded PowerShell or LOLBin activity afterward
- the actor also disabled Defender or cleared logs

## Suggested Response Actions
- Preserve registry and process evidence
- Validate whether the change was policy-driven or user-driven
- Re-enable logging settings if unauthorized
- Review recent and subsequent PowerShell activity on the host
- Search the same registry change pattern across other hosts
- Investigate related defense-evasion events for the same actor or device

## Analyst Notes
This is the stronger and broader PowerShell logging-evasion analytic in the pair. It should usually be preferred over narrow one-off registry checks because it better captures the wider set of ways attackers weaken PowerShell visibility.