# Mass File Rename or Encryption Burst

## Goal
Identify rapid file operations across multiple directories consistent with ransomware encryption, destructive modification, or bulk rename behavior.

## Why This Alert Matters
Ransomware and other destructive tooling often touch large numbers of files in a short time, especially across many directories. A burst of creates, modifies, or renames by a single process can indicate encryption, content corruption, or bulk destructive processing. This guide is based on a rule that looks for unusually high file-operation volume across multiple paths within a 10-minute window. :contentReference[oaicite:11]{index=11}

## What the Detection Is Looking For
This detection reviews `DeviceFileEvents` with actions such as:
- `FileCreated`
- `FileModified`
- `FileRenamed`

It summarizes activity by:
- device
- account
- initiating process
- command line
- number of unique paths touched

The rule triggers when both file-operation count and directory spread are high. :contentReference[oaicite:12]{index=12}

## Likely ATT&CK Mapping
- **T1486** – Data Encrypted for Impact

## Initial Triage Questions
1. Which process made the file changes?
2. How many files and paths were affected?
3. Did the process create unusual file extensions or ransom notes?
4. Is the process trusted, signed, and expected?
5. Was the host running backup, sync, migration, or bulk processing software?
6. Did shadow copy deletion, log clearing, or boot tampering occur nearby?
7. Is the behavior consistent with ransomware or legitimate mass processing?

## Key Fields To Review
- `DeviceName`
- `InitiatingProcessAccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `Timestamp`
- `FileOps`
- `Paths`
- `SamplePaths`
- `SampleFiles`

## Investigation Steps

### 1. Identify the process responsible
- Review the process name, signer, path, and parent process.
- Determine whether the process is:
  - trusted backup or sync tooling
  - document conversion software
  - suspicious or newly dropped binary
  - LOLBin or script-driven process

### 2. Review file-change patterns
- Look for:
  - extension changes
  - new encrypted-style extensions
  - ransom note filenames
  - repeated rename behavior
  - patterns across many user directories

### 3. Correlate with anti-recovery activity
Check for:
- shadow copy deletion
- boot/recovery tampering
- Defender disable attempts
- event log clearing
- service or scheduled task creation

### 4. Validate benign mass-processing context
- Confirm whether the host was doing:
  - bulk migration
  - indexing
  - sync
  - approved conversion or packaging
- If not, treat the event as high priority.

### 5. Assess spread and urgency
- Determine whether the activity is isolated to one folder set or rapidly affecting the broader host.
- If ongoing, immediate containment may be required.

## Common Benign Explanations
- Bulk file migrations or legitimate conversion jobs
- Backup, indexing, or sync products that touch many files
- Large-scale content processing by approved business tools :contentReference[oaicite:13]{index=13}

## Escalate When
Escalate if:
- the process is unknown or suspicious
- file extensions or ransom-note behavior appear
- the activity affects many directories quickly
- there is concurrent shadow copy deletion or recovery tampering
- the host is not expected to run heavy file-processing tools

## Suggested Response Actions
- Preserve process and file telemetry immediately
- Isolate the host if destructive encryption is likely
- Review impacted paths and estimate blast radius
- Look for ransom notes, extension patterns, and recovery impairment
- Search the environment for the same process or extension pattern
- Coordinate with IR and backup teams right away

## Analyst Notes
This is one of the highest-priority endpoint impact detections when malicious context is present. The combination of file-operation volume, directory spread, and related anti-recovery behavior is especially important.