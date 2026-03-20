# Remote Service Creation

## Goal
Identify service control activity used to create or start services on remote systems, which may indicate lateral movement or remote execution.

## Why This Alert Matters
Attackers frequently use service creation to execute payloads on remote hosts after gaining credentials or administrative access. Tools such as `sc.exe`, `psexec.exe`, and related service-control methods are common in both red-team activity and real intrusions.

## What the Detection Is Looking For
This detection looks for process execution involving:
- `sc.exe`
- `psexec.exe`
- `cmd.exe`

and command-line indicators associated with remote service actions such as:
- remote host references
- ` create `
- ` start `

## Likely ATT&CK Mapping
- T1021.002 – SMB/Windows Admin Shares
- T1569.002 – Service Execution

## Initial Triage Questions
1. What remote host was targeted?
2. What service name or binary path was used?
3. Was the activity expected for this account or admin workflow?
4. Was there evidence of credential theft, remote file copy, or privilege escalation beforehand?
5. Did the remote service launch a suspicious payload?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the service-control action
- Confirm which utility was used.
- Review the full command line for:
  - target host
  - service name
  - binary path
  - start behavior
- Determine whether the command was interactive, scripted, or launched by another tool.

### 2. Identify the remote target
- Extract the hostname or target reference from the command line.
- Determine whether the target is a server, workstation, admin jump box, or sensitive asset.
- Check whether the same target was involved in other alerts.

### 3. Review the initiating account and process lineage
- Determine whether the account is authorized for remote administration.
- Review parent and child process relationships.
- Look for preceding credential access, token theft, or suspicious admin utilities.

### 4. Correlate with adjacent lateral movement behavior
Check for:
- remote logons
- admin share access
- file copy to remote systems
- scheduled task creation
- WMI-based remote execution
- PsExec-style artifacts

### 5. Assess the payload
- Determine what binary or command was configured to run.
- Review signer, path, reputation, and whether it is expected.
- Check whether it launched from temp paths, shares, or unusual locations.

## Common Benign Explanations
- Authorized remote administration
- Software deployment systems
- Enterprise orchestration tools
- Helpdesk or infrastructure maintenance

## Escalate When
Escalate if:
- the account is not expected to perform remote service actions
- the payload path is suspicious or untrusted
- other lateral movement or credential abuse indicators exist
- the action targets multiple hosts
- the user or admin cannot explain the behavior

## Suggested Response Actions
- preserve the full command line and process tree
- capture the target host and service details
- review remote host execution and service-install events
- isolate impacted systems if malicious propagation is suspected
- notify IR for possible lateral movement containment

## Analyst Notes
This is the primary service-based lateral movement guide. It is broader and more useful than the older `sc.exe`/`wmic.exe`-focused version because it also accounts for common remote execution patterns such as PsExec-style behavior.