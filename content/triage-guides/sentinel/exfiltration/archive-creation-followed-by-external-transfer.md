# Archive Creation Followed by External Transfer

## Goal
Identify archive creation in user data paths followed closely by external network transfer activity that may indicate staging and exfiltration.

## Why This Alert Matters
A common exfiltration pattern is to first collect and compress files into an archive, then transfer that archive to an external destination. Compression reduces volume, groups targeted files together, and can make exfiltration easier to automate. When archive creation is quickly followed by external network activity on the same device, the sequence may reflect intentional staging and data removal. This guide is based on a rule that correlates archive creation events in user data paths with outbound connections to non-private IP space shortly afterward. :contentReference[oaicite:9]{index=9}

## What the Detection Is Looking For
This detection correlates:
- archive creation in user-accessible locations
- external network transfer activity from the same device

Archive file types include:
- `.zip`
- `.7z`
- `.rar`

The archive side focuses on paths such as:
- `\Users\`
- `\Desktop\`
- `\Documents\`
- `\Downloads\`

The outbound side reviews external connections and summarizes destinations contacted shortly after archive creation. :contentReference[oaicite:10]{index=10}

## Likely ATT&CK Mapping
- **T1560** – Archive Collected Data
- **T1048** – Exfiltration Over Alternative Protocol

## Initial Triage Questions
1. What archive was created, and where?
2. Which process created the archive?
3. Did external network traffic begin shortly after archive creation?
4. What destinations were contacted?
5. Is the user or device expected to create archives in those locations?
6. Was the archive later uploaded, emailed, or copied elsewhere?
7. Were there earlier collection indicators before the archive was created?

## Key Fields To Review
- `ArchiveTime`
- `Timestamp`
- `DeviceName`
- `ArchiveUser`
- `ArchiveProc`
- `ArchiveFile`
- `ArchivePath`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `ConnCount`
- `Destinations`
- `IPs`

## Investigation Steps

### 1. Review the archive creation event
- Identify the archive filename and path.
- Determine what process created it.
- Check whether the archive location is normal for the host and user.
- Look for file creation patterns suggesting bulk staging before the archive appeared.

### 2. Review the external transfer activity
- Inspect the remote destinations, IPs, URLs, and timing.
- Determine whether the outbound activity began immediately or soon after archive creation.
- Review which process initiated the external transfer.

### 3. Check what was likely collected
Look for:
- bulk file access
- document access
- browser credential store access
- clipboard collection
- staging in temp or user-writable locations
- preceding collection or archive utility usage

### 4. Validate legitimate business context
- Confirm whether the user was:
  - packaging files for approved transfer
  - doing backup or migration work
  - preparing software release artifacts
- Determine whether the destination is expected and approved.

### 5. Correlate with exfiltration methods
Check for:
- OneDrive or cloud upload spikes
- email exfiltration
- WinSCP usage
- AzCopy, AWS CLI, or gsutil usage
- uncommon-port transfer
- removable media activity

## Common Benign Explanations
- Legitimate user archiving followed by approved upload or transfer
- Backup, migration, or packaging workflows
- Software release preparation :contentReference[oaicite:11]{index=11}

## Escalate When
Escalate if:
- the archive is created in a suspicious user path without business reason
- the archive is followed by immediate external transfer
- the destination is unapproved, suspicious, or newly observed
- the user is not expected to perform large file packaging
- there are nearby collection, credential-access, or staging indicators

## Suggested Response Actions
- Preserve the archive filename, path, and creating process
- Review file-access activity leading up to archive creation
- Investigate and block suspicious external destinations if needed
- Collect the archive if safely possible
- Search for similar archive-plus-transfer sequences across the environment
- Isolate the endpoint if malicious staging and transfer are confirmed

## Analyst Notes
This is a strong sequence-based exfiltration analytic because it captures both staging and outbound transfer. It becomes even stronger when paired with document collection, cloud upload, or email exfiltration signals.