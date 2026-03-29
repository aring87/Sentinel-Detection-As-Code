# Disable Script Block Logging

## Goal
Identify registry changes that disable PowerShell Script Block Logging, reducing visibility into attacker PowerShell activity.

## Why This Alert Matters
PowerShell Script Block Logging is one of the most useful sources of visibility for malicious script execution. Attackers may disable it before or during PowerShell abuse to hide encoded commands, download cradles, obfuscated content, or post-exploitation scripts. Changes that set Script Block Logging-related values to disabled should be treated seriously, especially when tied to suspicious PowerShell execution.

## What the Detection Is Looking For
This detection reviews `DeviceRegistryEvents` for registry modifications involving Script Block Logging and checks for values consistent with disabling the control, especially where the registry data is set to `0`.

This older rule is specifically focused on direct disablement of Script Block Logging via registry change.

## Likely ATT&CK Mapping
- **T1562** – Impair Defenses

## Initial Triage Questions
1. Which registry key was changed?
2. What value was written?
3. Which process made the registry modification?
4. Was the change made by Group Policy, script, or interactive process?
5. Did the host recently run PowerShell or LOLBins?
6. Is the device receiving an expected policy update?
7. Were other logging or security settings also changed?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `RegistryKey`
- `RegistryValueData`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- account context if available

## Investigation Steps

### 1. Validate the registry modification
- Confirm the full registry path.
- Determine whether the key is tied to:
  - Script Block Logging
  - PowerShell policy control
- Verify whether the value change would disable or weaken logging.

### 2. Identify the initiating process
- Review the process responsible for the modification.
- Determine whether it was:
  - `powershell.exe`
  - `reg.exe`
  - a script host
  - a policy engine
  - an installer or management platform

### 3. Review surrounding PowerShell activity
Look for:
- encoded commands
- `Invoke-Expression`
- `DownloadString`
- suspicious child processes
- LOLBin activity
- external network traffic from PowerShell

### 4. Validate policy or admin context
- Check whether the host recently received a legitimate policy update.
- Confirm whether the change was approved by administrators or part of a test.
- Determine whether the host is in a lab or controlled environment.

### 5. Search for broader defense evasion
- Look for:
  - Defender preference changes
  - event log clearing
  - security tool disablement
  - AMSI bypass indicators
  - persistence creation after the logging change

## Common Benign Explanations
- Very limited, but possible in lab or testing environments
- Controlled security validation
- Rare policy or troubleshooting changes

## Escalate When
Escalate if:
- Script Block Logging is explicitly disabled
- the initiating process is suspicious or user-driven
- the host also shows PowerShell abuse
- related logging or Defender settings are changed nearby
- there is no approved policy or maintenance context

## Suggested Response Actions
- Preserve registry and process telemetry
- Identify the exact scope of PowerShell logging impairment
- Review recent PowerShell executions on the host
- Re-enable logging controls if unauthorized
- Search for the same registry pattern across the environment
- Investigate the account and process responsible for the change

## Analyst Notes
This rule is useful as a narrow detection for direct Script Block Logging disablement. It is best interpreted together with broader PowerShell logging weakening and follow-on script execution activity.