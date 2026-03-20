# Event Viewer UAC Bypass Registry Hijack

## Goal
Identify registry hijack activity associated with the classic Event Viewer UAC bypass technique.

## Why This Alert Matters
The Event Viewer UAC bypass abuses a per-user registry hijack so that launching Event Viewer causes an attacker-controlled command to execute with elevated behavior. This is a strong privilege escalation and defense evasion signal because it uses a native Windows binary and a trusted launch path.

## What the Detection Is Looking For
This detection looks for registry activity on:
- `\Software\Classes\mscfile\shell\open\command`

with actions such as:
- `RegistryValueSet`
- `RegistryKeyCreated`

## Likely ATT&CK Mapping
- T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control

## Initial Triage Questions
1. What command was registered under the hijacked key?
2. Which process and user wrote the registry value?
3. Was the registry write interactive, scripted, or part of a suspicious installer?
4. Did `mmc.exe` or `eventvwr.exe` launch afterward?
5. Did the elevated execution lead to persistence, service creation, or payload execution?

## Key Fields To Review
- Timestamp
- DeviceName
- InitiatingProcessAccountName
- InitiatingProcessFileName
- RegistryKey
- RegistryValueData

## Investigation Steps
### 1. Validate the registry hijack
- Confirm the exact registry path modified.
- Review the command stored in `RegistryValueData`.
- Determine whether it points to:
  - PowerShell
  - CMD
  - script files
  - LOLBins
  - user-writable paths

### 2. Review the writer context
- Identify the process that made the registry modification.
- Determine whether the change was user-driven, scripted, or installer-driven.
- Check parent process lineage for suspicious chains.

### 3. Correlate with Event Viewer launches
- Search for later `eventvwr.exe` or `mmc.exe` execution.
- Determine whether those launches were followed by child processes or elevated payload execution.

### 4. Assess follow-on behavior
Review the same host for:
- service creation
- scheduled task creation
- Run key persistence
- suspicious PowerShell
- dropped payloads in user-writable paths

## Common Benign Explanations
- Rare troubleshooting or software repair actions
- Authorized UAC bypass research in a controlled lab

## Escalate When
Escalate if:
- the hijacked command is suspicious
- the writing process is unexpected
- `eventvwr.exe` or `mmc.exe` launched afterward
- additional persistence or execution behavior followed
- the user cannot explain the change

## Suggested Response Actions
- preserve the modified registry value and initiating process details
- capture the referenced payload
- remove or revert the hijacked registry key if malicious
- review later Event Viewer launches and child processes
- hunt for the same registry path changes across the environment

## Analyst Notes
Use this as the canonical Event Viewer UAC bypass guide. It is much stronger than the older process-only rule because it detects the underlying hijack mechanism rather than only the later launch symptom.