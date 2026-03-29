# Service Binary Path Hijack

## Goal
Identify suspicious service creation or configuration changes that set a service image path to uncommon or user-writable locations.

## Why This Alert Matters
Services are a durable persistence and privilege mechanism on Windows. Attackers may create or reconfigure services so they launch payloads from `AppData`, `Temp`, `ProgramData`, or `Users\Public`, gaining persistence and often execution with elevated privileges. This guide is based on a rule that looks for service-related commands combined with references to common writable or nonstandard paths. :contentReference[oaicite:26]{index=26}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `sc.exe`
- `powershell.exe`
- `pwsh.exe`

It looks for service-related actions such as:
- `create`
- `config`
- `New-Service`
- `Set-Service`

and requires command-line references to locations such as:
- `AppData`
- `Temp`
- `ProgramData`
- `Users\Public` :contentReference[oaicite:27]{index=27}

## Likely ATT&CK Mapping
- **T1543.003** – Create or Modify System Process: Windows Service

## Initial Triage Questions
1. What service name was created or modified?
2. What image path or binary path was configured?
3. Does the path point to a writable or nonstandard location?
4. Was the service created by an expected admin or installer?
5. Was the target binary unsigned, newly dropped, or suspicious?
6. Did the host show recent file drops or service-start activity?
7. Could this also support privilege escalation in addition to persistence?

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

### 1. Review the service configuration command
- Extract the service name and image path.
- Determine whether the service was:
  - newly created
  - reconfigured
  - pointed to a new binary location
- Confirm whether the path is standard or suspicious.

### 2. Inspect the image path
- Determine whether it points to:
  - trusted program files
  - system directories
  - `AppData`
  - `Temp`
  - `ProgramData`
  - `Users\Public`
- Nonstandard writable paths strongly increase suspicion.

### 3. Review the referenced binary
- Check whether the binary is:
  - signed
  - known-good
  - recently created
  - launched from an unusual parent process
- Review nearby file-write events for the same path.

### 4. Correlate with service behavior
Look for:
- service start events
- process creation from the new service path
- network connections from the launched binary
- persistence overlap with tasks or Run keys
- Defender tampering or other suspicious admin actions

### 5. Validate benign admin context
- Some internal applications may use nonstandard service paths, but this should be documented.
- Confirm whether the service change aligns with:
  - approved testing
  - internal software deployment
  - packaging or development workflows

## Common Benign Explanations
- Approved service testing or troubleshooting
- Internal application deployment to nonstandard paths
- Rare packaging or development workflows :contentReference[oaicite:28]{index=28}

## Escalate When
Escalate if:
- the service path points to a writable or suspicious location
- the referenced binary is unsigned or newly dropped
- the actor is not expected to create or modify services
- there are related persistence or loader indicators nearby
- the service appears designed to run attacker tooling with elevated privileges

## Suggested Response Actions
- Preserve the full command line and service details
- Inspect the configured service on the host
- Collect the referenced binary if safe to do so
- Search for the same service name or image path elsewhere
- Disable or revert unauthorized service changes if appropriate
- Isolate the endpoint if malicious service persistence is confirmed

## Analyst Notes
This is a strong persistence and possible privilege-escalation analytic. The most important triage factor is whether the service image path makes sense for the host and software involved.