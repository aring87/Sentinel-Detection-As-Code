# AD Explorer or Secrets Dump Tool on VDI or Administrative Host

## Goal
Identify suspicious use of directory exploration or credential dumping tooling on administrative systems, VDI platforms, or other high-value Windows hosts.

## Why This Alert Matters
Administrative and VDI systems often have broad visibility into identity infrastructure and may be used by privileged users. Tooling such as AD Explorer, secrets-dumping utilities, `ntdsutil`, or `esentutl` can indicate offline credential theft, unauthorized directory reconnaissance, or preparation for domain compromise. These tools are not inherently malicious, so the analyst’s job is to determine whether the tool use is expected in context.

## What the Detection Is Looking For
This detection reviews process creation telemetry for:
- tool execution such as:
  - `ADExplorer.exe`
  - `gosecretsdump.exe`
  - `secretsdump.py`
  - `ntdsutil.exe`
  - `esentutl.exe`
- command-line indicators such as:
  - `ntds.dit`
  - `SYSTEM`
  - `save HKLM\SYSTEM`
  - `ifm`
  - `drsuapi`

## Likely ATT&CK Mapping
- T1003.003 – OS Credential Dumping: NTDS
- T1087 – Account Discovery
- T1018 – Remote System Discovery
- T1078 – Valid Accounts

## Initial Triage Questions
1. Which tool ran, and on what class of system?
2. Is the host used by directory admins, IR staff, or support engineers who might legitimately run this tool?
3. Did the command line reference `ntds.dit`, registry hives, or other credential stores?
4. Was this activity preceded by unusual sign-in, lateral movement, or vCenter-based disk access?
5. Did the same host stage archives, connect externally, or perform follow-on persistence?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine
- InitiatingProcessFileName
- SHA1
- SHA256
- ReportId

## Investigation Steps
### 1. Validate the tool execution
- Confirm the exact executable or script used.
- Review the full command line for:
  - target data sources
  - remote domain controller references
  - output paths
  - registry hive access
- Determine whether the tool ran interactively or through a scripted chain.

### 2. Classify the host and account
- Determine whether the system is:
  - a VDI host
  - an admin workstation
  - a jump box
  - a domain controller
  - a regular user system
- Check whether the account is expected to run directory or IR tooling.

### 3. Assess surrounding identity activity
Look for:
- LDAP enumeration
- privileged group queries
- Kerberos abuse
- recent logons to domain controllers
- vCenter or backup activity tied to offline extraction
- outbound staging or archive creation

### 4. Inspect files and outputs
- Identify whether the tool created:
  - dump files
  - archives
  - copied hive files
  - directory snapshots
- Determine where outputs were stored and whether they were later transferred.

### 5. Validate business context
- Confirm whether the activity aligns with:
  - IR investigation
  - red team exercise
  - directory migration
  - backup validation
  - AD troubleshooting
- Verify with the appropriate admin team before closing as benign.

## Common Benign Explanations
- Authorized DFIR activity
- Red team or purple team operations
- AD troubleshooting
- Migration or backup workflows
- Legitimate admin directory analysis

## Escalate When
Escalate if:
- the tool ran on an unexpected host
- the actor is not a recognized privileged admin or responder
- command lines reference `ntds.dit` or registry hive extraction
- output files were staged, compressed, or transferred
- the same host shows suspicious discovery, lateral movement, or exfiltration

## Suggested Response Actions
- preserve the process tree and any output files
- identify whether credential material or snapshots were created
- review related access to domain controllers and sensitive shares
- collect hashes and paths for the executed tools
- expand the investigation to other systems used by the same actor

## Analyst Notes
Tools in this category often sit at the edge of admin and adversary behavior. Context is everything: host role, operator identity, output handling, and related activity usually determine whether this is benign admin work or high-risk credential access.
