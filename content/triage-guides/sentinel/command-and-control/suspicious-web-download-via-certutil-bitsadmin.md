# Suspicious Web Download via Certutil or Bitsadmin

## Goal
Identify use of built-in Windows utilities to download content from remote locations, which may indicate payload staging, tooling transfer, or command-and-control setup.

## Why This Alert Matters
`certutil.exe` and `bitsadmin.exe` are built-in Windows utilities frequently abused by attackers because they can retrieve remote content without requiring third-party download tools. Their use is especially suspicious when tied to unusual users, writable paths, or follow-on execution.

## What the Detection Is Looking For
This detection reviews process creation activity for:
- `certutil.exe`
- `bitsadmin.exe`

It looks for command-line patterns suggesting remote download behavior, including:
- `http://`
- `https://`
- `/transfer`
- `/addfile`
- `-urlcache`
- `download`

The rule is meant to catch built-in transfer utility abuse used for staging payloads or tooling.

## Likely ATT&CK Mapping
- **T1105** – Ingress Tool Transfer

## Initial Triage Questions
1. Which built-in utility was used, `certutil` or `bitsadmin`?
2. What remote URL or destination was referenced?
3. Was the download written to a suspicious or user-writable path?
4. Was the downloaded content later executed?
5. Is the command part of an approved administrative or deployment workflow?
6. What process or parent launched the utility?
7. Is there related persistence, script execution, or network activity nearby?

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

### 1. Review the command line
- Confirm whether the command includes:
  - a URL
  - transfer arguments
  - cache or download syntax
- Extract the destination URL and any local output path.
- Determine whether the command is consistent with:
  - file download
  - staging
  - transfer queue creation

### 2. Inspect the destination path
- Check whether the file was written to:
  - `Temp`
  - `Downloads`
  - `ProgramData`
  - `Users\Public`
  - `AppData`
- Review whether the location is normal for the host and user.

### 3. Check for follow-on execution
- Look for process creation events involving the downloaded file.
- Check whether the file was:
  - executed
  - archived
  - registered
  - loaded via PowerShell, CMD, MSHTA, or Rundll32

### 4. Validate administrative context
- Determine whether the account normally uses built-in transfer utilities.
- Check if the activity matches:
  - software distribution
  - patch retrieval
  - certificate operations
  - legacy automation
- Review any related tickets or maintenance windows.

### 5. Investigate the remote source
- Check domain reputation, hosting provider, and whether the destination is newly observed.
- Determine whether the source is:
  - a known vendor
  - an internal mirror
  - suspicious infrastructure
  - a file-hosting or paste-style site

## Common Benign Explanations
- Approved software distribution or update tasks
- Administrator troubleshooting downloads
- Legacy scripts using built-in transfer utilities
- Internal automation or package retrieval

## Escalate When
Escalate if:
- the URL or domain is suspicious
- the file is written to a writable or unusual location
- the downloaded content is later executed
- the command is launched by an unusual parent process
- the user is not expected to use `certutil` or `bitsadmin`
- there is nearby persistence, script execution, or remote access activity

## Suggested Response Actions
- Preserve the full command line and related file events
- Retrieve the downloaded file for analysis
- Block or investigate the destination URL or IP
- Search for the same command pattern across the environment
- Isolate the host if malicious payload execution is confirmed
- Review related persistence or credential-access activity on the device

## Analyst Notes
This is a foundational built-in-tool abuse detection. It is valuable on its own, but much stronger when linked to writable-path execution, encoded PowerShell, browser-to-script chains, or remote-access-driven intrusion activity.