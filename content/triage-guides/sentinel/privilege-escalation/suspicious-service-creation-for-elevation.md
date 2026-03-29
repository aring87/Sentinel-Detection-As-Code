# Suspicious Service Creation for Elevation

## Goal
Identify service creation or configuration commands that may be used to execute code with SYSTEM privileges.

## Why This Alert Matters
Windows services run with powerful privileges and are a common path for privilege escalation and persistence. Attackers may create or modify services so a chosen binary or script runs as SYSTEM. This guide is based on a rule that watches for service-related commands in `sc.exe`, `cmd.exe`, `powershell.exe`, and `pwsh.exe`, especially those containing `create`, `New-Service`, `binPath=`, or `Set-Service`. :contentReference[oaicite:10]{index=10}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where the process is:
- `sc.exe`
- `cmd.exe`
- `powershell.exe`
- `pwsh.exe`

and the command line contains indicators such as:
- ` create `
- `New-Service`
- `binPath=`
- `Set-Service` :contentReference[oaicite:11]{index=11}

## Likely ATT&CK Mapping
- **T1543.003** – Create or Modify System Process: Windows Service

## Initial Triage Questions
1. What service name was created or modified?
2. What `binPath` or payload path was configured?
3. Does the service point to a script, LOLBin, or unsigned binary?
4. Is the creating user expected to manage services on this host?
5. Was the referenced file newly created or dropped recently?
6. Did the service start successfully and launch a process?
7. Is this clearly persistence, privilege escalation, or both?

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

### 1. Review the service command
- Extract the service name and action.
- Determine whether the event:
  - created a new service
  - changed an existing one
  - set a new `binPath`
- Note whether it was done through `sc.exe` or PowerShell.

### 2. Inspect the payload path
- Determine whether the configured binary path points to:
  - a normal service location
  - `System32`
  - `Program Files`
  - `AppData`
  - `Temp`
  - `Users\Public`
  - scripts or LOLBins
- Writable or odd paths raise suspicion.

### 3. Review file and process context
- Check whether the referenced binary or script:
  - exists
  - is signed
  - was recently written
  - was launched afterward
- Correlate with service start or child-process activity if available.

### 4. Correlate with related privilege activity
Look for:
- token manipulation or SeDebug use
- UAC bypass indicators
- DLL injection tooling
- recent credential dumping
- persistence changes
- suspicious parent process chains

### 5. Validate legitimate admin context
- Confirm whether the event aligns with:
  - service deployment
  - software installation
  - endpoint management
  - packaging or maintenance
- If not, treat as higher risk.

## Common Benign Explanations
- Legitimate service deployments by administrators
- Approved software installation workflows
- Endpoint management or software packaging tools :contentReference[oaicite:12]{index=12}

## Escalate When
Escalate if:
- the service points to a writable-path or suspicious payload
- the user is not expected to create or modify services
- the binary is unsigned or newly dropped
- the host shows related UAC bypass, token abuse, or persistence activity
- the service appears designed to gain SYSTEM for attacker code

## Suggested Response Actions
- Preserve the full command line and service details
- Review the resulting service configuration on the endpoint
- Collect the referenced binary or script if safe
- Search for the same service name or path across other hosts
- Disable or revert unauthorized service changes if appropriate
- Isolate the host if malicious service-based elevation is confirmed

## Analyst Notes
This is a strong privilege-escalation analytic because service abuse remains a common way to run attacker code as SYSTEM. The payload path is usually the fastest way to judge severity.