# Suspicious Service Creation for Elevation

## Goal
Identify local service creation commands that may be used to gain SYSTEM-level execution.

## Why This Alert Matters
Creating or configuring a Windows service is a classic way to obtain elevated execution because services often run as SYSTEM. Unlike the lateral movement service rules, this one focuses on local elevation and persistence-style service creation on the host where the command was run.

## What the Detection Is Looking For
This detection looks for:
- `sc.exe`
- `cmd.exe`
- `powershell.exe`

with command-line indicators such as:
- ` create `
- `New-Service`
- `binPath=`

## Likely ATT&CK Mapping
- T1543.003 – Create or Modify System Process: Windows Service

## Initial Triage Questions
1. What service name and binary path were specified?
2. Should this user be creating services on the host?
3. Was the binary legitimate, signed, and stored in a trusted path?
4. Did the service start successfully afterward?
5. Was there a dropped payload or privilege escalation chain nearby?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the service creation command
- Review the full command line.
- Extract the service name, binary path, and whether `binPath=` points to an expected executable.
- Determine whether the action was performed through `sc.exe`, CMD, or PowerShell.

### 2. Inspect the target binary
- Check signer, reputation, path, and recent file creation time.
- Determine whether the payload lives in:
  - `AppData`
  - `Temp`
  - `ProgramData`
  - user profile directories
  - other nonstandard locations

### 3. Review initiator context
- Determine whether the user should be creating services.
- Review parent process lineage and whether the action followed UAC bypass, token abuse, or another suspicious launch path.

### 4. Correlate with service start and file activity
- Look for service start events on the same host.
- Check for nearby file creation events that dropped the service binary.
- Determine whether the service launched child processes or created persistence.

## Common Benign Explanations
- Legitimate service deployments by administrators
- Software installation workflows

## Escalate When
Escalate if:
- the service path is suspicious or user-writable
- the user is not expected to create services
- the service binary is unsigned or newly dropped
- the activity follows UAC bypass or token abuse
- multiple persistence or elevation indicators appear together

## Suggested Response Actions
- preserve the full command line and service configuration
- collect the referenced service binary
- review service start events and resulting child processes
- disable or remove the service if malicious
- hunt for the same service name or binary elsewhere

## Analyst Notes
This is the primary local service-based privilege escalation guide. Keep it separate from your lateral movement service-creation guide, because this one is focused on gaining SYSTEM privileges on the local host rather than executing remotely.