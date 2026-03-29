# Event Viewer UAC Bypass Registry Hijack

## Goal
Identify registry hijack activity associated with the Event Viewer UAC bypass technique.

## Why This Alert Matters
UAC bypass techniques can allow an attacker to execute code with elevated privileges without triggering the normal consent experience. The Event Viewer method relies on hijacking the `mscfile\shell\open\command` registry path so that when Event Viewer or related management consoles are launched, a malicious command runs instead. This guide is based on a rule that watches for registry writes or key creation under `\Software\Classes\mscfile\shell\open\command`. :contentReference[oaicite:7]{index=7}

## What the Detection Is Looking For
This detection reviews `DeviceRegistryEvents` where:
- `RegistryKey` contains:
  - `\Software\Classes\mscfile\shell\open\command`
- and the action is:
  - `RegistryValueSet`
  - `RegistryKeyCreated`

It surfaces the writing process, command line, registry value name, and registry value data. :contentReference[oaicite:8]{index=8}

## Likely ATT&CK Mapping
- **T1548.002** – Abuse Elevation Control Mechanism: Bypass User Account Control

## Initial Triage Questions
1. What value was written under the hijacked key?
2. Does the value point to `cmd`, `PowerShell`, `mshta`, or another interpreter?
3. Which process and user wrote the registry value?
4. Was the change interactive, scripted, or dropped by another process?
5. Did `eventvwr.exe` or `mmc.exe` execute soon afterward?
6. Is the host used for UAC-bypass research or security testing?
7. Were there related registry hijacks, service changes, or suspicious elevated child processes?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `InitiatingProcessAccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `RegistryKey`
- `RegistryValueName`
- `RegistryValueData`
- `ReportId`

## Investigation Steps

### 1. Review the registry write
- Confirm the exact registry path.
- Identify the value name and data written.
- Determine whether the value launches:
  - `cmd.exe`
  - `powershell.exe`
  - `mshta.exe`
  - `rundll32.exe`
  - another binary or script

### 2. Identify the writing process
- Review the process name, path, signer, and parent.
- Determine whether the change came from:
  - user-launched scripting
  - `reg.exe`
  - PowerShell
  - malware or dropper activity
  - approved lab tooling

### 3. Check for follow-on elevated execution
Look for:
- `eventvwr.exe`
- `mmc.exe`
- elevated child processes
- suspicious scripts or LOLBins launched after the registry change
- integrity-level changes if available

### 4. Correlate with broader privilege-escalation behavior
Check for:
- token manipulation
- service creation for elevation
- suspicious scheduled tasks
- additional registry hijacks
- defender tampering
- log clearing

### 5. Validate benign context
- Very rare legitimate software repair or lab research may touch this path.
- Confirm whether the device is a controlled testing asset before downgrading the event.

## Common Benign Explanations
- Rare troubleshooting or software repair actions
- Authorized UAC research in a lab :contentReference[oaicite:9]{index=9}

## Escalate When
Escalate if:
- the value points to an interpreter or suspicious binary
- `eventvwr.exe` or `mmc.exe` launches soon afterward
- the writing process is unexpected or user-driven
- the host shows other privilege-escalation or defense-evasion behavior
- there is no credible lab or research explanation

## Suggested Response Actions
- Preserve the registry event and full value data
- Export or capture the affected registry key
- Review related elevated process activity
- Remove unauthorized hijack values if compromise is confirmed
- Search for the same registry path modification across the environment
- Isolate the host if active privilege escalation is underway

## Analyst Notes
This is a high-value UAC bypass analytic because it focuses on the core registry hijack used by the technique rather than only looking for a follow-on process name.