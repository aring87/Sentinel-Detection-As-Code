# Remote Scheduled Task Creation

## Goal
Identify `schtasks.exe` usage that creates scheduled tasks on remote systems, which may indicate lateral movement or remote execution.

## Why This Alert Matters
Scheduled tasks are a common technique for executing commands on remote Windows systems using valid credentials. Attackers may use remote task creation to run payloads, establish persistence on another host, or move laterally while blending in with administrative tooling.

## What the Detection Is Looking For
This detection looks for:
- `schtasks.exe`
- command-line indicators such as:
  - `/create`
  - `/s`

## Likely ATT&CK Mapping
- T1053.005 – Scheduled Task
- T1021 – Remote Services

## Initial Triage Questions
1. What remote host was targeted?
2. What task name and command were specified?
3. Is remote task creation normal for the initiating account?
4. Was there remote logon, service creation, or file copy activity nearby?
5. Did the task run successfully on the target system?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- ProcessCommandLine
- InitiatingProcessFileName

## Investigation Steps
### 1. Validate the remote task creation
- Confirm `schtasks.exe` execution.
- Review the full command line for:
  - target system
  - task name
  - scheduled action or binary
  - run-as context
  - trigger timing
- Determine whether the command indicates immediate execution or delayed scheduling.

### 2. Identify the remote target and payload
- Extract the `/s` target host.
- Determine what command or binary the task was configured to launch.
- Assess whether the payload lives in:
  - a trusted program path
  - temp directories
  - admin shares
  - copied staging locations

### 3. Review the initiating account
- Determine whether the account normally performs orchestration or admin operations.
- Check for remote logon events and admin share access from the same account.
- Review whether the account is privileged or newly active.

### 4. Correlate with nearby lateral movement
Search for:
- remote service creation
- WMI remote execution
- SMB file copy
- credential dumping or reuse
- suspicious process launches on the target host

### 5. Assess impact on the target host
- Determine whether the scheduled task executed.
- Review child process activity on the destination endpoint.
- Check for persistence or repeated task creation across multiple systems.

## Common Benign Explanations
- Approved admin orchestration
- Enterprise job scheduling
- Configuration management
- Helpdesk or deployment operations

## Escalate When
Escalate if:
- the task command is suspicious or points to an untrusted binary
- the account does not normally administer remote systems
- multiple targets are involved
- other lateral movement indicators exist
- the target host launched malicious child processes

## Suggested Response Actions
- capture the full command line, task name, and target host
- inspect scheduled task artifacts on the destination endpoint
- review remote logons and share access for the same account
- isolate affected hosts if propagation is suspected
- notify IR for lateral movement investigation

## Analyst Notes
This should be the canonical scheduled-task lateral movement guide. It is stronger than the older variants because it specifically keys on remote creation semantics and includes better triage context.