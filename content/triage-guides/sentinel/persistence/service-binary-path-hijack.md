# Service Binary Path Hijack

## Goal
Identify suspicious service creation or configuration changes that point a service to execute from uncommon or user-writable paths, potentially establishing persistence or privilege escalation.

## Why This Alert Matters
Services often run with elevated privileges, so hijacking a service image path can give an attacker durable persistence and potentially SYSTEM-level execution. The standardized rule is more operationally useful than the older registry-only rule because it focuses on actual service configuration commands and suspicious writable locations.

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `sc.exe`
- `powershell.exe`

with command-line patterns such as:
- `create`
- `config`
- `New-Service`
- `Set-Service`

and suspicious location indicators such as:
- `AppData`
- `Temp`
- `ProgramData`

## Likely ATT&CK Mapping
- T1543.003 – Windows Service
- also relevant to Privilege Escalation in some cases

## Initial Triage Questions
1. What service was created or modified?
2. What binary path was assigned to the service?
3. Is the path user-writable, unsigned, or otherwise suspicious?
4. Was the service recently started, and what did it execute?
5. Did a payload get dropped to the same path before the service change?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the service change
- Confirm whether a service was created or reconfigured.
- Review the exact command line for:
  - service name
  - binary path
  - start type
  - account context
- Determine whether the path points to a normal program directory or a user-writable location.

### 2. Inspect the target binary
- Review signer, hash, reputation, and compilation metadata if available.
- Check whether the binary or script was recently written to disk.
- Determine whether it is stored in:
  - `AppData`
  - `Temp`
  - `ProgramData`
  - other nonstandard or writable folders

### 3. Review initiator context
- Identify who made the change.
- Determine whether the account normally installs or reconfigures services.
- Review parent process lineage and whether PowerShell or another script launched the change.

### 4. Correlate with surrounding behavior
Look for:
- suspicious file drops
- scheduled task creation
- Run key persistence
- service start events
- remote service creation or lateral movement
- privilege escalation behavior

### 5. Assess impact
- Determine whether the modified service already started.
- Review child process activity and any SYSTEM-context execution.
- Search for the same service name or payload across other hosts.

## Common Benign Explanations
- Approved service testing or troubleshooting
- Internal application deployment to nonstandard paths
- Lab or packaging activity

## Escalate When
Escalate if:
- the path is clearly user-writable or abnormal
- the payload is unsigned, newly dropped, or suspicious
- the service name is masquerading as a legitimate Windows component
- the initiator is not expected to manage services
- the service change correlates with other persistence or privilege escalation behavior

## Suggested Response Actions
- preserve the service configuration details and command line
- collect the referenced binary or script
- check whether the service has started or was set to auto-start
- revert or disable the service if malicious
- hunt for the same binary path and service name elsewhere

## Analyst Notes
Prefer this guide as the canonical service persistence workflow. The older rule looked only for `ImagePath` registry changes under `HKLM\SYSTEM\CurrentControlSet\Services`, while the standardized rule is better for triage because it directly captures service creation/configuration commands and flags suspicious writable paths.