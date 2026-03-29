# Potential LSASS Memory Dump

## Goal
Identify execution patterns commonly associated with dumping LSASS memory to extract credentials.

## Why This Alert Matters
LSASS dumping is one of the most important credential-access behaviors to detect because it can provide attackers with plaintext credentials, hashes, or Kerberos material needed for privilege escalation and lateral movement. Even when the activity is performed with legitimate tools or built-in DLLs, it is often a high-severity signal.

This rule detects common command-line artifacts and tools associated with LSASS dumping activity.

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for command-line content or process names associated with LSASS dump attempts, including:
- `lsass`
- `MiniDumpWriteDump`
- `comsvcs.dll`
- `MiniDump`
- `procdump`
- `sekurlsa`

It also explicitly watches for:
- `procdump.exe`
- `procdump64.exe`
- `rundll32.exe`
- `mimikatz.exe`

## Likely ATT&CK Mapping
- **T1003.001** – OS Credential Dumping: LSASS Memory

## Initial Triage Questions
1. Which dumping utility or command-line pattern triggered the alert?
2. Was LSASS explicitly targeted in the command line?
3. Did the process run under an administrative or SYSTEM context?
4. Was a dump file written to disk?
5. Was the dumping tool expected for DFIR, EDR, or authorized testing?
6. Did the same host show privilege escalation, token abuse, or lateral movement?
7. Was the tool launched from a suspicious or user-writable path?

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

### 1. Identify the dumping method
- Review which utility or command-line pattern matched.
- Determine whether the activity used:
  - `procdump`
  - `rundll32` with `comsvcs.dll`
  - Mimikatz-style strings
  - a custom or renamed tool

### 2. Check execution context
- Identify the account and integrity level if available.
- Determine whether the process ran as:
  - administrator
  - SYSTEM
  - a service account
- Review parent process ancestry for suspicious launch chains.

### 3. Look for dump file creation
- Search nearby file events for:
  - `.dmp`
  - archive files
  - temporary output files
- Check common locations such as:
  - `Temp`
  - `ProgramData`
  - `Users\Public`
  - `AppData`

### 4. Correlate with related activity
Look for:
- token abuse
- service creation
- scheduled tasks
- remote logons
- lateral movement
- exfiltration or staging
- archive creation shortly after dump activity

### 5. Validate benign context
- Confirm whether the host is:
  - a security lab system
  - used for incident response
  - used by EDR or memory forensic tooling
- Check whether there was an approved support or investigation reason for memory capture.

## Common Benign Explanations
- Approved memory forensics
- EDR or authorized security tooling
- Red-team or purple-team exercises
- Rare support or crash-dump workflows

## Escalate When
Escalate if:
- LSASS is clearly referenced in the command
- the utility is launched from an unusual or writable path
- a dump file is created and staged
- the actor is not approved for security or admin activity
- the host shows related credential theft, lateral movement, or exfiltration
- Mimikatz or comsvcs-style dumping behavior is present

## Suggested Response Actions
- Preserve process, command-line, and file telemetry
- Locate and quarantine any generated dump files
- Isolate the host if malicious credential dumping is confirmed
- Review recent successful logons and privileged activity on the host
- Search for the same tool, command line, or hash across the environment
- Reset or protect impacted credentials as appropriate

## Analyst Notes
This is a high-priority credential-access alert. Even when false positives are possible, LSASS-related dumping behavior should receive careful review because of its close link to account compromise and follow-on privilege abuse.