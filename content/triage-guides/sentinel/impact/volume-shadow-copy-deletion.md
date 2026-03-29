# Volume Shadow Copy Deletion

## Goal
Identify deletion of shadow copies using built-in Windows utilities, a common ransomware precursor and anti-recovery action.

## Why This Alert Matters
Shadow copies are frequently targeted by ransomware and destructive tooling because they enable local recovery. Deleting them reduces the ability to restore files and increases the impact of encryption or other destructive operations. This guide is based on a rule that detects built-in utilities associated with shadow copy deletion and WMI-based removal behavior. :contentReference[oaicite:17]{index=17}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `vssadmin.exe`
- `wmic.exe`
- `powershell.exe`
- `cmd.exe`

It looks for command-line content such as:
- `delete shadows`
- `shadowcopy delete`
- `Win32_Shadowcopy`
- `vssadmin delete shadows`
- `Get-WmiObject Win32_ShadowCopy`
- `Remove-WmiObject` :contentReference[oaicite:18]{index=18}

## Likely ATT&CK Mapping
- **T1490** – Inhibit System Recovery

## Initial Triage Questions
1. Which utility was used to delete shadow copies?
2. Was the deletion authorized or part of maintenance?
3. Which account and parent process initiated the action?
4. Did the host show mass file modification or encryption nearby?
5. Were event logs cleared or boot recovery settings changed around the same time?
6. Was the utility launched from a suspicious execution path?
7. Is the host a server, workstation, or lab system?

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

### 1. Review the deletion command
- Determine whether the command used:
  - `vssadmin`
  - `wmic`
  - PowerShell WMI
  - CMD-wrapped execution
- Confirm whether the command would remove all or some shadow copies.

### 2. Identify the actor and process chain
- Review the user, parent process, and execution path.
- Determine whether the activity came from:
  - admin maintenance
  - backup tooling
  - suspicious script or LOLBin chain
  - ransomware-associated process tree

### 3. Correlate with destructive behavior
Look for:
- mass file rename or encryption burst
- boot or recovery tampering
- Defender disable attempt
- event log clearing
- archive staging
- unusual external traffic or exfiltration

### 4. Validate legitimate maintenance
- Confirm whether the action aligns with:
  - approved backup maintenance
  - restore testing
  - lab validation
  - rare admin troubleshooting
- If not, treat it as high priority.

### 5. Assess recovery risk
- Determine whether the host now lacks local recovery points.
- Coordinate with IR and backup teams if destructive activity is ongoing.

## Common Benign Explanations
- Approved backup maintenance or restore workflows
- Lab validation or recovery testing
- Rare administrative troubleshooting :contentReference[oaicite:19]{index=19}

## Escalate When
Escalate if:
- shadow copies were deleted unexpectedly
- the same host shows encryption, log clearing, or recovery tampering
- the parent process is suspicious or user-driven
- the user is not expected to perform backup or restore operations

## Suggested Response Actions
- Preserve process and command-line evidence
- Review whether shadow copies still exist on the host
- Isolate the endpoint if destructive activity is active
- Search for the same deletion pattern elsewhere
- Coordinate with backup teams to assess restoration options
- Investigate related ransomware or impact indicators immediately

## Analyst Notes
This is one of the highest-value anti-recovery detections on Windows endpoints. Shadow copy deletion alone is serious; when paired with file-encryption activity it becomes urgent.