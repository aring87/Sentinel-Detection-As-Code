# Potential Remote SMB Encryption From Single Source Host

## Goal
Identify high-volume file modifications over SMB from a single source that may indicate remote encryption or destructive file operations across network shares.

## Why This Alert Matters
Some ransomware families encrypt files remotely over SMB shares rather than locally on each target. This can allow a single compromised system to impact many files on other hosts or shared storage. High-volume SMB file access or modification from one source host to many targets in a short time is a strong signal of possible remote encryption or destructive propagation. This guide is based on a rule that uses `SecurityEvent` SMB access telemetry to find bursts of share activity from one source. :contentReference[oaicite:14]{index=14}

## What the Detection Is Looking For
This detection reviews `SecurityEvent` records for:
- `EventID 5145`
- `EventID 5140`

It extracts:
- share name
- source IP
- user
- relative target name

The rule then summarizes high-volume share activity and triggers when file touches or unique target counts exceed thresholds. :contentReference[oaicite:15]{index=15}

## Likely ATT&CK Mapping
- **T1486** – Data Encrypted for Impact
- **T1021.002** – SMB/Windows Admin Shares

## Initial Triage Questions
1. Which source host and source IP generated the SMB activity?
2. Which user account was involved?
3. How many files or targets were touched?
4. Were administrative shares or broad file shares involved?
5. Is the source system expected to perform bulk SMB writes?
6. Are there signs of ransomware, rename bursts, or ransom notes on impacted systems?
7. Did the source host also show credential theft, remote admin, or Quick Assist/RMM activity?

## Key Fields To Review
- `TimeGenerated`
- `Computer`
- `Ip`
- `User`
- `FileTouchCount`
- `Targets`
- `Shares`
- `SampleTargets`

## Investigation Steps

### 1. Identify the source host
- Determine which system initiated the SMB activity.
- Confirm whether it is:
  - backup infrastructure
  - deployment server
  - file-management platform
  - normal workstation
  - newly suspicious endpoint

### 2. Review share and target scope
- Identify which shares were accessed.
- Determine whether the activity involved:
  - normal file shares
  - admin shares
  - broad cross-directory write behavior
- Review sample target names for evidence of encryption or rename patterns.

### 3. Look for impact indicators on destination systems
Check for:
- file extension changes
- ransom notes
- file rename bursts
- shadow copy deletion
- boot tampering
- endpoint process anomalies on impacted hosts

### 4. Investigate the source host for compromise
- Review whether the source also shows:
  - LSASS dumping
  - token abuse
  - Quick Assist or RMM sessions
  - scheduled task or service creation
  - PowerShell or LOLBin staging
- A compromised admin workstation or helpdesk system can be a high-risk origin.

### 5. Validate benign bulk-share operations
- Confirm whether the source system is part of:
  - backup jobs
  - software deployment
  - migration or content replication
- If not, prioritize immediate containment.

## Common Benign Explanations
- Backup software
- Large-scale file migration
- Enterprise software deployment touching many shares :contentReference[oaicite:16]{index=16}

## Escalate When
Escalate if:
- a normal workstation is writing to many SMB targets rapidly
- the source is not expected to perform bulk SMB operations
- impacted targets show encryption or ransom-note behavior
- the source host also shows credential theft or remote-admin abuse
- admin shares are heavily involved without clear reason

## Suggested Response Actions
- Preserve SMB, authentication, and endpoint telemetry
- Isolate the source host if malicious remote encryption is suspected
- Review impacted shares and hosts for encryption artifacts
- Search for similar SMB-write bursts from other source systems
- Coordinate with IR, AD, and file-share owners immediately
- Protect backup and recovery systems from follow-on impact

## Analyst Notes
This is a strong hybrid impact/lateral-movement analytic. It is especially important when a single source host suddenly writes at scale across shares or admin paths.