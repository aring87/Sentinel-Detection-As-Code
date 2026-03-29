# Net Group and Domain Trust Discovery

## Goal
Identify use of built-in Windows tools to enumerate group membership, domain information, and trust relationships.

## Why This Alert Matters
Attackers frequently use built-in commands like `net.exe`, `nltest.exe`, `dsquery.exe`, and `whoami.exe` to learn how a domain is structured and where privileged access may exist. Group and trust discovery can reveal opportunities for privilege escalation, lateral movement, and targeting of administrative paths. This guide is based on a rule that looks for those built-in tools with trust-, group-, and account-related arguments. :contentReference[oaicite:6]{index=6}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `net.exe`
- `net1.exe`
- `nltest.exe`
- `dsquery.exe`
- `whoami.exe`

It looks for command-line patterns such as:
- `group`
- `localgroup`
- `/domain`
- `/all_trusts`
- `/trusted_domains`
- `/user` :contentReference[oaicite:7]{index=7}

## Likely ATT&CK Mapping
- **T1069** – Permission Groups Discovery
- **T1482** – Domain Trust Discovery
- **T1087** – Account Discovery

## Initial Triage Questions
1. Which built-in tool was used?
2. Was the command targeting group membership, trust relationships, or account context?
3. Is the user expected to perform domain reconnaissance?
4. Did the activity occur on an admin workstation, jump box, or user endpoint?
5. Was the activity followed by remote execution or credential access?
6. Is the command part of a helpdesk or audit workflow?
7. Are there multiple discovery tools being used together?

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

### 1. Identify the discovery objective
- Review the command line and determine whether the user was enumerating:
  - domain groups
  - local groups
  - domain membership
  - trust relationships
  - current user identity or privileges

### 2. Assess host and user context
- Determine whether the host is:
  - a helpdesk/admin system
  - server
  - standard user endpoint
- Confirm whether the account normally performs administrative discovery.

### 3. Look for multi-tool recon chains
- Check whether the same device or account also used:
  - `whoami`
  - `nltest`
  - `dsquery`
  - PowerShell LDAP queries
  - `net user`
  - DNS lookup tools
- A burst of several discovery tools is more suspicious than a single command.

### 4. Review follow-on activity
Look for:
- failed logon bursts
- LSASS dumping
- token or privilege abuse
- WMI or service-based lateral movement
- remote scheduled task creation
- archive staging or exfiltration

### 5. Validate administrative purpose
- Confirm whether the command was tied to:
  - support activity
  - audits
  - troubleshooting
  - compliance checks
- If not, treat the discovery behavior more seriously.

## Common Benign Explanations
- Domain administration and helpdesk support
- Inventory or audit scripts :contentReference[oaicite:8]{index=8}

## Escalate When
Escalate if:
- multiple built-in reconnaissance tools are used together
- the user is not expected to enumerate groups or trusts
- the commands run from a non-admin workstation
- there is nearby credential access or remote execution
- the activity appears staged or bursty rather than isolated

## Suggested Response Actions
- Preserve process and command-line evidence
- Review the same user and host for additional discovery activity
- Correlate with authentication, remote-execution, and persistence events
- Search for similar group or trust discovery commands across the environment
- Suppress only when tied to clearly documented admin workflows

## Analyst Notes
Built-in discovery commands are common, so context matters. This analytic becomes much stronger when paired with LDAP enumeration, account discovery, failed logons, or lateral movement.