# LDAP Enumeration Using PowerShell

## Goal
Identify PowerShell-based Active Directory and LDAP enumeration that may indicate domain discovery, user or computer enumeration, or privilege reconnaissance.

## Why This Alert Matters
PowerShell is commonly used by both administrators and attackers to query Active Directory. Adversaries use LDAP and AD cmdlets to enumerate users, groups, computers, and domain structure, often as a precursor to privilege escalation, lateral movement, or credential access. This guide is based on a rule looking for PowerShell command lines containing AD and LDAP enumeration patterns. :contentReference[oaicite:3]{index=3}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for `powershell.exe` or `pwsh.exe` command lines containing AD and LDAP discovery patterns such as:
- `Get-ADUser`
- `Get-ADComputer`
- `Get-ADGroup`
- `Get-ADObject`
- `DirectorySearcher`
- `LDAP://`
- `ADSISearcher`
- `Get-DomainUser`
- `Get-DomainComputer` :contentReference[oaicite:4]{index=4}

## Likely ATT&CK Mapping
- **T1087.002** – Account Discovery: Domain Account
- **T1018** – Remote System Discovery

## Initial Triage Questions
1. Which AD or LDAP query pattern matched?
2. Was the command executed by a normal admin, script, or unusual user?
3. Is the system an admin workstation, jump box, or normal endpoint?
4. Did the query target users, groups, computers, or a broader directory search?
5. Is PowerView-style or ADSI-style enumeration involved?
6. Was the activity followed by credential access, lateral movement, or privilege escalation?
7. Does the host normally run PowerShell-based AD discovery?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `ReportId`

## Investigation Steps

### 1. Identify the enumeration method
- Review the command line and determine whether the query used:
  - AD module cmdlets
  - raw LDAP syntax
  - `DirectorySearcher`
  - ADSI
  - PowerView-like commands
- Note whether the activity is broad enumeration or a targeted query.

### 2. Determine user and host role
- Confirm whether the user is:
  - domain admin
  - helpdesk
  - engineer
  - ordinary user
- Determine whether the host is used for administrative activity.

### 3. Assess scope of the query
- Determine whether the command targeted:
  - accounts
  - computers
  - groups
  - trusts
  - OUs or broader directory structure
- Broad or repeated enumeration is more suspicious than a single admin query.

### 4. Correlate with post-enumeration behavior
Look for:
- `net.exe`, `whoami.exe`, `nltest.exe`, `dsquery.exe`
- failed logon bursts
- LSASS dumping
- token manipulation
- scheduled task or service creation
- remote process execution
- archive creation or exfiltration

### 5. Validate benign admin context
- Review whether the command was part of:
  - support workflows
  - inventory scripts
  - audit or compliance collection
  - identity administration
- If the context is unclear, prioritize based on host role and user privilege.

## Common Benign Explanations
- Approved AD administration and support work
- Identity inventory scripts
- Lab or validation testing :contentReference[oaicite:5]{index=5}

## Escalate When
Escalate if:
- the query runs on a non-admin endpoint
- the user is not expected to query AD
- PowerView-style or broad directory search behavior is present
- the activity is followed by credential access or lateral movement
- the same host also shows failed logons, remote execution, or persistence

## Suggested Response Actions
- Preserve the full PowerShell command line
- Review recent directory, authentication, and remote-execution activity for the same user
- Investigate whether the host was used as a staging point for further intrusion
- Search for the same commands or patterns across the environment
- Tune only after validating recurring benign identity workflows

## Analyst Notes
This is one of the stronger discovery detections when PowerShell is used outside of normal administration paths. The best discriminator is whether the user and host are expected to run AD enumeration at all.