# Whoami and Net Enumeration Burst

## Goal
Identify bursts of account, trust, and environment-enumeration commands that may indicate host or domain reconnaissance.

## Why This Alert Matters
Attackers often use built-in Windows commands to quickly profile a system and its surrounding domain environment. A burst of commands like `whoami`, `net`, `net1`, `nltest`, and `dsquery` can reveal local identity, domain membership, trust relationships, user and group information, and administrative opportunities. This guide is based on a rule that groups these commands over a 10-minute window and alerts when the command count exceeds a threshold. :contentReference[oaicite:9]{index=9}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `whoami.exe`
- `net.exe`
- `net1.exe`
- `nltest.exe`
- `dsquery.exe`

It summarizes:
- total command count
- command lines seen
- processes used

by device, account, and 10-minute window. The rule triggers when the burst is large enough to suggest meaningful reconnaissance rather than a single admin check. :contentReference[oaicite:10]{index=10}

## Likely ATT&CK Mapping
- **T1087** – Account Discovery
- **T1016** – System Network Configuration Discovery
- **T1482** – Domain Trust Discovery

## Initial Triage Questions
1. How many recon commands ran in the burst?
2. Which exact commands were executed?
3. Did the commands target local information, domain information, or trust data?
4. Is the account expected to perform domain reconnaissance?
5. Was the host an admin workstation, helpdesk box, or standard endpoint?
6. Did the burst occur before credential access, remote execution, or lateral movement?
7. Was the activity manual or part of a scripted or automated sequence?

## Key Fields To Review
- `DeviceName`
- `AccountName`
- `Timestamp`
- `CommandCount`
- `Commands`
- `Procs`

## Investigation Steps

### 1. Review the burst contents
- Inspect the collected command lines.
- Determine whether the sequence focused on:
  - account identity
  - group membership
  - trust relationships
  - domain membership
  - environment layout
- Multiple different discovery categories increase suspicion.

### 2. Assess user and host role
- Determine whether the account is:
  - helpdesk
  - domain admin
  - engineering or operations
  - standard user
- Determine whether the host is expected to perform administrative discovery.

### 3. Identify whether the activity was scripted
- Check process ancestry and timing.
- Decide whether the commands were:
  - typed manually
  - launched by a batch script
  - launched through PowerShell
  - run after another suspicious process or remote-access session

### 4. Correlate with adjacent activity
Look for:
- external lookup tool usage
- network scanner execution
- LDAP enumeration
- failed NTLM logons
- LSASS dumping
- service creation
- WMI or scheduled-task-based lateral movement

### 5. Validate benign admin context
- Confirm whether the activity aligns with:
  - admin troubleshooting
  - helpdesk account and trust checks
  - inventory or audit scripts
- If not, prioritize more aggressively.

## Common Benign Explanations
- Administrator troubleshooting or domain support activity
- Automated inventory or audit scripts
- Helpdesk account and trust verification workflows :contentReference[oaicite:11]{index=11}

## Escalate When
Escalate if:
- the burst occurs on a normal endpoint
- the user is not expected to perform domain discovery
- the command set includes trust or account-enumeration behavior
- the activity is followed by credential access or lateral movement
- the sequence appears automated or tied to a suspicious parent process

## Suggested Response Actions
- Preserve the full set of command lines
- Review recent and subsequent activity on the same host and user
- Search for the same burst pattern across other systems
- Correlate with authentication, privilege, and lateral-movement telemetry
- Tune only after confirming recurring benign admin or audit workflows

## Analyst Notes
This is a useful burst-style reconnaissance analytic because it captures a pattern of discovery rather than a single command. It becomes much stronger when followed by credential access, scanning, or remote execution.