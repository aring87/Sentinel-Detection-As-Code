# Archive Creation Followed by External Transfer

## Goal
Identify possible data staging for exfiltration where a user or process creates an archive file in common user-accessible paths and may then transfer it externally.

## Why This Alert Matters
Adversaries often collect files, compress them into archives such as ZIP, 7Z, or RAR, and then move them out of the environment through email, cloud storage, or direct network transfer. Archive creation in user profile paths can be benign, but it becomes more concerning when followed by outbound transfer behavior.

## What the Detection Is Looking For
This detection looks for archive files such as `.zip`, `.7z`, or `.rar` being created in user-related paths like:
- `Desktop`
- `Documents`
- `Downloads`
- user profile directories

## Likely ATT&CK Mapping
- T1560 – Archive Collected Data
- T1048 – Exfiltration Over Alternative Protocol

## Initial Triage Questions
1. Who created the archive?
2. What process created it?
3. What files were likely placed into the archive?
4. Did outbound network, email, browser upload, or cloud-sync activity happen soon after?
5. Is this normal for the user, admin, script, or application involved?

## Key Fields To Review
- Timestamp
- DeviceName
- InitiatingProcessAccountName
- InitiatingProcessFileName
- FileName
- FolderPath

## Investigation Steps
### 1. Validate the archive event
- Confirm the archive file name and full path.
- Check whether the path is a normal user working directory or an unusual staging location.
- Determine whether the file extension truly reflects an archive and not a renamed file.

### 2. Identify the creating process
- Review the initiating process.
- Look for tools such as:
  - `powershell.exe`
  - `cmd.exe`
  - `7z.exe`
  - `winrar.exe`
  - `tar.exe`
  - scripting engines or custom binaries
- Determine whether the parent process chain looks expected.

### 3. Determine user intent and business context
- Check whether the account normally packages files for support, development, or transfer workflows.
- Review recent help desk tickets, approved transfers, or backup tasks.
- Determine whether the archive creation aligns with the user’s job function.

### 4. Correlate with exfiltration activity
Review activity within the next 15 to 60 minutes for:
- browser uploads
- OneDrive or cloud upload spikes
- outbound email with attachments
- unusual outbound connections
- file transfer tools
- removable media usage

### 5. Assess contents and sensitivity
If available:
- inspect what files were added to the archive
- determine whether sensitive, regulated, or bulk data was involved
- check if the archive name suggests staging, export, backup, or collection

## Common Benign Explanations
- Legitimate user archiving
- Software packaging
- Backup preparation
- Normal transfer preparation for approved workflows

## Escalate When
Escalate if one or more of the following are true:
- archive creation is followed by outbound transfer behavior
- archive was created by suspicious scripting or LOLBins
- the user denies creating the archive
- the archive appears to contain sensitive or bulk data
- multiple collection/exfiltration alerts occur on the same host or user

## Suggested Response Actions
- isolate the host if active exfiltration is suspected
- block related external sessions or destinations if still active
- collect process tree and recent network telemetry
- preserve evidence of the archive path, hash, and associated process lineage
- notify data owner or incident response if sensitive data may be involved

## Analyst Notes
Archive creation alone is not enough to confirm malicious exfiltration. Confidence increases significantly when this alert correlates with cloud uploads, email attachments, or abnormal outbound traffic shortly after the archive is created.