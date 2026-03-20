# Boot Configuration or Recovery Tampering

## Goal
Identify attempts to disable Windows recovery features or alter boot configuration in ways that may hinder restoration during destructive attacks.

## Why This Alert Matters
Attackers may change boot or recovery settings to reduce recovery options, suppress boot failure handling, or make it harder for defenders to restore systems after ransomware or destructive activity.

## What the Detection Is Looking For
This detection looks for execution of:
- `bcdedit.exe`
- `reagentc.exe`

with command-line indicators such as:
- `recoveryenabled no`
- `bootstatuspolicy ignoreallfailures`
- `/disable`

## Likely ATT&CK Mapping
- T1490 – Inhibit System Recovery
- T1562 – Impair Defenses

## Initial Triage Questions
1. Was the boot or recovery change approved?
2. Which account and process chain initiated it?
3. Did shadow copy deletion or encryption behavior occur nearby?
4. Is this endpoint undergoing imaging, repair, or hardware maintenance?
5. Is the command consistent with ransomware or destructive tooling?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the command
- Confirm whether `bcdedit.exe` or `reagentc.exe` executed.
- Review the full command line for disabling or failure-suppression logic.
- Determine whether the action was local, scripted, remote, or policy-driven.

### 2. Review user and process lineage
- Identify the account performing the action.
- Review parent process and surrounding execution.
- Look for suspicious launch sources such as:
  - PowerShell
  - remote admin tools
  - scheduled tasks
  - unknown binaries
  - malware staging scripts

### 3. Correlate with destructive behavior
Check for:
- shadow copy deletion
- mass file rename/encryption bursts
- event log clearing
- security control tampering
- recovery partition or system repair interference

### 4. Validate operational context
- Determine whether the system was being reimaged, repaired, or serviced.
- Check change windows, maintenance records, and support tickets.
- Confirm whether the account is authorized to make boot/recovery changes.

### 5. Assess scope
- Search for the same command-line patterns on other endpoints.
- Determine whether this is isolated admin work or a campaign affecting multiple hosts.

## Common Benign Explanations
- Approved maintenance
- Hardware repair
- OS deployment or imaging
- Lab or test activity

## Escalate When
Escalate if:
- no approved maintenance explains the activity
- the command appears shortly before or during encryption/destructive activity
- suspicious parent processes or remote tools are involved
- the same behavior appears on multiple systems
- the account context is abnormal

## Suggested Response Actions
- isolate the host if destructive activity is underway
- preserve process chain and command-line evidence
- check system recovery state and backup posture
- search for related shadow copy deletion and encryption indicators
- notify IR and platform/recovery owners

## Analyst Notes
This alert is particularly important when paired with shadow copy deletion. The combination strongly suggests an attempt to inhibit system recovery before or during destructive impact.