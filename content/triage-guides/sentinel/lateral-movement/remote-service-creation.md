# Remote Service Creation

## Goal
Identify service-control commands used to create or start services on remote systems for lateral movement or remote execution.

## Why This Alert Matters
Remote service creation is a classic attacker technique because it enables execution as a service on another system, often using administrative shares, copied binaries, or LOLBins. Tools like `sc.exe`, `PsExec`, and related command chains are commonly used once an attacker has privileged credentials. This guide is based on a rule that detects process creation involving `sc.exe`, `psexec.exe`, or `cmd.exe` with UNC path references and service-control actions like `create`, `start`, or `config`. :contentReference[oaicite:6]{index=6}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `sc.exe`
- `psexec.exe`
- `cmd.exe`

and requires:
- a UNC path reference such as `\\`
- service-related action words like:
  - `create`
  - `start`
  - `config`

The rule surfaces the process, command line, parent process, and hash so the analyst can understand what remote system and service were targeted. :contentReference[oaicite:7]{index=7}

## Likely ATT&CK Mapping
- **T1021.002** – SMB/Windows Admin Shares
- **T1569.002** – Service Execution

## Initial Triage Questions
1. What remote host was targeted?
2. What service name and binary path were referenced?
3. Was the binary copied to an administrative share beforehand?
4. Is the initiating account expected to create or start remote services?
5. Was `PsExec` involved, or just `sc.exe` / command-shell wrapping?
6. Did the service point to a script, LOLBin, or payload from a suspicious location?
7. Were there preceding logons, file copies, or credential-access events?

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

### 1. Review the remote service command
- Extract the remote host, service name, and action.
- Determine whether the command:
  - creates a new service
  - starts an existing service
  - reconfigures a service
- Look closely at any `binPath=` or payload references.

### 2. Identify the payload path
- Determine whether the service points to:
  - a trusted application path
  - `System32`
  - a UNC path
  - `C$`, `ADMIN$`, or another admin share
  - `Temp`, `ProgramData`, `Users\Public`, or `AppData`
- Service paths in writable or share-based locations are higher risk.

### 3. Check for prior staging
Look for:
- SMB copy activity
- file drops to admin shares
- `psexec` usage
- remote logons
- scheduled task creation
- WMI execution
- credential theft or privileged logons

### 4. Validate admin or deployment context
- Determine whether the source host is:
  - a patch-management server
  - deployment/orchestration system
  - admin workstation
  - normal endpoint
- Confirm whether the user normally performs remote service work.

### 5. Assess whether execution occurred
- Review whether the service started successfully.
- Check the target host for:
  - new service events
  - launched child processes
  - file writes
  - persistence or follow-on movement

## Common Benign Explanations
- Authorized remote administration
- Software deployment systems
- Patch management or endpoint management tooling :contentReference[oaicite:8]{index=8}

## Escalate When
Escalate if:
- the service points to a suspicious payload or writable path
- the source host is not expected to perform remote service work
- there was preceding credential access or remote file copy activity
- the target host is high value
- `PsExec` or `sc.exe` activity appears user-driven rather than management-driven

## Suggested Response Actions
- Preserve the full command line and process ancestry
- Identify the target host and inspect the created or modified service
- Review related file copies to admin shares
- Search for the same service name or payload path elsewhere
- Contain source or target hosts if malicious service execution is confirmed
- Review privileged accounts involved in the action

## Analyst Notes
This is a high-value lateral-movement analytic because service-based remote execution remains common in real intrusions. Context about the source host, target host, and payload path is the fastest way to separate benign administration from malicious movement.