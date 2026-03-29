# Boot Configuration or Recovery Tampering

## Goal
Identify attempts to disable recovery options or alter boot configuration in ways that may hinder recovery during destructive attacks.

## Why This Alert Matters
Attackers, especially ransomware operators, often try to reduce recovery options before or during destructive activity. Modifying boot configuration or disabling recovery can make it harder for defenders and users to restore systems after encryption or other damage. This guide is based on a rule that looks for `bcdedit.exe` and `reagentc.exe` command lines associated with disabling or weakening recovery behavior. :contentReference[oaicite:5]{index=5}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `bcdedit.exe`
- `reagentc.exe`

It looks for command-line content such as:
- `recoveryenabled no`
- `bootstatuspolicy ignoreallfailures`
- `/disable`
- `reagentc /disable` :contentReference[oaicite:6]{index=6}

## Likely ATT&CK Mapping
- **T1490** – Inhibit System Recovery
- **T1562** – Impair Defenses

## Initial Triage Questions
1. Which recovery or boot setting was changed?
2. Was the change approved maintenance or unexpected activity?
3. Which account and process made the change?
4. Did the host show ransomware staging, shadow copy deletion, or mass file modification nearby?
5. Is the host a workstation, server, image-build system, or lab asset?
6. Did the same actor also clear logs or tamper with security controls?
7. Was the command launched from a normal admin workflow or suspicious parent process?

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

### 1. Review the exact recovery or boot change
- Determine whether the command disabled:
  - recovery mode
  - boot failure handling
  - Windows recovery environment
- Confirm whether the setting materially reduces restoration options.

### 2. Identify the initiating context
- Review the user, parent process, and execution path.
- Determine whether the action came from:
  - an admin console
  - PowerShell or CMD wrapper
  - a deployment tool
  - suspicious malware or script chain

### 3. Correlate with destructive activity
Look for:
- shadow copy deletion
- mass file rename or encryption
- log clearing
- Defender tampering
- service or scheduled task persistence
- unusual process execution shortly before or after the command

### 4. Validate legitimate maintenance
- Confirm whether the host was undergoing:
  - imaging
  - hardware repair
  - approved OS maintenance
  - controlled lab testing
- If not, treat the event as higher priority.

### 5. Assess recovery impact
- Determine whether the host has lost normal rollback or recovery options.
- Coordinate with infrastructure support if recovery settings must be restored quickly.

## Common Benign Explanations
- Rare approved maintenance or recovery workflows
- OS imaging or hardware repair activity
- Lab validation involving recovery configuration changes :contentReference[oaicite:7]{index=7}

## Escalate When
Escalate if:
- recovery settings were disabled without approved maintenance
- the host also shows ransomware or destructive behavior
- the same actor tampered with logs, Defender, or shadow copies
- the change was launched by a suspicious or unexpected parent process

## Suggested Response Actions
- Preserve the process and command-line evidence
- Confirm current recovery configuration on the endpoint
- Review nearby destructive or anti-recovery activity
- Restore recovery settings if unauthorized
- Isolate the host if broader malicious activity is confirmed

## Analyst Notes
This is a strong anti-recovery signal. It is especially important when paired with shadow copy deletion, file-encryption bursts, or security-control tampering.