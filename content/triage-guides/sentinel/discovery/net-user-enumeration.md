# Net User Enumeration

## Goal
Identify use of `net.exe` or `net1.exe` to enumerate user accounts locally or in the domain.

## Why This Alert Matters
`net user` is a common built-in command, but it is also a classic attacker reconnaissance technique for learning valid account names and understanding the environment before credential attacks or lateral movement. While benign use is common in support and administration, unexpected use on ordinary endpoints can be a useful signal. This guide is based on a rule that looks for `net.exe` or `net1.exe` with `user` in the command line. :contentReference[oaicite:9]{index=9}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `net.exe`
- `net1.exe`

It looks for command lines containing `user`, which may indicate:
- local account listing
- domain account listing
- user-specific account lookup :contentReference[oaicite:10]{index=10}

## Likely ATT&CK Mapping
- **T1087.001** – Account Discovery: Local Account

## Initial Triage Questions
1. Was the command enumerating local users or domain users?
2. Is the user or host expected to run `net user`?
3. Did the activity occur as part of helpdesk or admin troubleshooting?
4. Were other discovery commands executed nearby?
5. Was the system a user workstation or admin system?
6. Was the activity followed by failed logons or credential access?
7. Is the command part of a broader reconnaissance pattern?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `ReportId`

## Investigation Steps

### 1. Determine the exact command usage
- Review whether the command used:
  - `net user`
  - `net user /domain`
  - a specific username
- Determine whether the intent was listing all users or checking a particular account.

### 2. Validate system and user role
- Confirm whether the system is:
  - a helpdesk/admin machine
  - server
  - user endpoint
- Determine whether the initiating user normally performs account checks.

### 3. Look for related discovery activity
Check for:
- `whoami`
- `net group`
- `nltest`
- `dsquery`
- LDAP PowerShell queries
- DNS or external lookup tool execution

### 4. Review follow-on credential or access attempts
- Look for:
  - failed NTLM logons
  - password spray patterns
  - remote login attempts
  - LSASS dumping
  - browser credential access

### 5. Validate benign support context
- Confirm whether the command matches:
  - helpdesk troubleshooting
  - account verification
  - inventory script activity
  - lab validation

## Common Benign Explanations
- Helpdesk or administrative account troubleshooting
- Inventory or support scripts
- Lab validation activity :contentReference[oaicite:11]{index=11}

## Escalate When
Escalate if:
- `net user` appears on a non-admin workstation without explanation
- the same user performs multiple discovery commands nearby
- the activity is followed by failed logons or credential access
- the account being used is not expected to perform user enumeration
- the host shows signs of broader attacker discovery behavior

## Suggested Response Actions
- Preserve the command line and process context
- Review adjacent discovery and authentication events
- Search for the same account performing enumeration on other systems
- Investigate whether the command was part of broader reconnaissance or spray preparation
- Tune only after validating known support workflows

## Analyst Notes
This is a useful low- to medium-confidence discovery signal. It is most valuable when grouped with other built-in reconnaissance commands or authentication anomalies.