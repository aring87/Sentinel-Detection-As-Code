# Whoami and Net Enumeration Burst

## Goal
Identify bursts of host and domain enumeration commands that may indicate local or domain reconnaissance activity.

## Why This Alert Matters
Attackers often chain together commands like `whoami`, `net user`, `net group`, `nltest`, and `dsquery` to quickly understand account context, domain relationships, trust configuration, and available targets. A burst pattern is more suspicious than a single command because it suggests active recon rather than casual troubleshooting.

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for commands such as:
- `whoami.exe`
- `net.exe`
- `nltest.exe`
- `dsquery.exe`

and flags hosts/accounts with:
- 5 or more enumeration commands
- within a 10-minute window

## Likely ATT&CK Mapping
- T1087 – Account Discovery
- T1016 – System Network Configuration Discovery
- T1482 – Domain Trust Discovery

## Initial Triage Questions
1. What exact commands were run in the burst?
2. Is the account expected to perform domain or host enumeration?
3. Was this admin troubleshooting, inventory collection, or suspicious discovery?
4. Did the same user later access remote systems or credentials?
5. Is the host a workstation, admin jump box, or server?

## Key Fields To Review
- DeviceName
- AccountName
- Timestamp bucket
- CommandCount
- Commands

## Investigation Steps
### 1. Validate the burst
- Review the exact set of commands in the 10-minute window.
- Determine whether the commands focused on:
  - account discovery
  - local admin discovery
  - domain trust discovery
  - network/share enumeration
- Assess whether the sequence looks scripted or manual.

### 2. Review account and host context
- Determine whether the user is expected to do admin troubleshooting.
- Review whether the host role supports this kind of activity.
- Check whether the behavior is common for that account.

### 3. Correlate with follow-on activity
Look for:
- remote service sign-ins
- WMI or service-based lateral movement
- SMB access
- credential dumping or LSASS access
- archive creation or exfiltration

### 4. Review process ancestry
- Determine whether a script, scheduled task, or remote session launched the commands.
- Check whether they were run from an interactive shell, PowerShell, or admin tool.

## Common Benign Explanations
- Administrator troubleshooting
- Domain support operations
- Inventory or audit scripts
- Lab validation

## Escalate When
Escalate if:
- the user is not expected to perform domain recon
- the commands are unusually dense or scripted
- lateral movement or credential access follows
- the activity occurs on a compromised or suspicious host
- the same pattern appears on multiple endpoints

## Suggested Response Actions
- preserve the command burst and initiating process context
- review nearby auth, remote access, and credential events
- validate whether the account is authorized for this activity
- hunt for the same pattern across the environment
- escalate to IR if the sequence appears malicious or unexplained

## Analyst Notes
This guide sits between reconnaissance and discovery. Keep it in your recon folder if you want a pre-lateral-movement hunting view, but its ATT&CK mapping also overlaps with Discovery, which is normal for this type of behavior.