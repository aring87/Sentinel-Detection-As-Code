# Mass File Rename or Encryption Burst

## Goal
Identify rapid file modification activity across many folders that may indicate ransomware encryption or other destructive bulk file operations.

## Why This Alert Matters
Ransomware commonly touches large numbers of files in a short time across multiple directories. Even before a ransom note appears, a sudden burst of file operations can be an early sign of encryption or destructive impact.

## What the Detection Is Looking For
This detection looks for a high volume of file operations over a 10-minute window and requires:
- at least 500 file operations
- activity across at least 10 distinct folder paths

## Likely ATT&CK Mapping
- T1486 – Data Encrypted for Impact

## Initial Triage Questions
1. What process is making the file changes?
2. Is the process trusted and expected on this host?
3. Are files being renamed, encrypted, or otherwise bulk-modified?
4. Were ransom notes dropped?
5. Was shadow copy deletion or recovery tampering observed around the same time?

## Key Fields To Review
- DeviceName
- InitiatingProcessAccountName
- InitiatingProcessFileName
- Timestamp bucket
- File operation counts
- Distinct folder path counts

## Investigation Steps
### 1. Confirm the burst
- Validate that file operation volume is truly abnormal.
- Determine whether activity is isolated to a single user profile, shared drive, or broad portions of the host.
- Review whether the burst repeats across multiple time windows.

### 2. Identify the process
- Determine the executable performing the changes.
- Evaluate whether it is:
  - ransomware or suspicious binary
  - scripting engine
  - document conversion tool
  - sync client
  - backup/indexing software
- Review signer, reputation, install path, and parent process.

### 3. Inspect file characteristics
- Look for extension changes typical of encryption.
- Check for ransom notes or text/html instructions.
- Review whether files became inaccessible or were renamed in a consistent pattern.

### 4. Correlate with recovery inhibition
Search for nearby:
- volume shadow copy deletion
- `vssadmin`/`wmic` shadow operations
- `bcdedit` or `reagentc` recovery tampering
- security tool disable attempts
- log clearing

### 5. Assess blast radius
- Determine whether only one host is affected or if there is multi-host spread.
- Review the same process hash, account, and command line across the environment.
- Check whether network shares or removable media were impacted.

## Common Benign Explanations
- Bulk file migrations
- Approved conversion jobs
- Indexing software
- Backup/sync products
- Mass rename tools used by administrators or content teams

## Escalate When
Escalate if:
- files appear encrypted or renamed in suspicious patterns
- ransom notes are present
- the process is untrusted or unknown
- shadow copy deletion or recovery tampering also occurred
- multiple devices show the same behavior

## Suggested Response Actions
- isolate the host immediately if encryption is active
- stop or contain the offending process if appropriate
- preserve process, hash, and file extension evidence
- identify impacted shares and downstream systems
- engage IR and recovery teams quickly

## Analyst Notes
This analytic is a strong ransomware-impact signal, especially when combined with shadow copy deletion or boot/recovery tampering on the same device.