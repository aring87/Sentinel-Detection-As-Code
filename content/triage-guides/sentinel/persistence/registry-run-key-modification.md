# Registry Run Key Modification

## Goal
Identify creation or modification of common autorun registry keys used for persistence.

## Why This Alert Matters
Run keys are one of the most common Windows persistence mechanisms. Malware, scripts, and even some loaders can add or modify autorun entries so code executes at logon or startup. While installers and enterprise configuration tools also use these keys, suspicious values pointing to writable paths, unknown binaries, or scripts can indicate malicious persistence. This guide is based on a rule that detects value sets or key creation under common Run and RunOnce paths. :contentReference[oaicite:23]{index=23}

## What the Detection Is Looking For
This detection reviews `DeviceRegistryEvents` where:
- the registry key is one of:
  - `\Software\Microsoft\Windows\CurrentVersion\Run`
  - `\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
- the action is:
  - `RegistryValueSet`
  - `RegistryKeyCreated`

It surfaces the device, creating account, process name, registry key, and written value data. :contentReference[oaicite:24]{index=24}

## Likely ATT&CK Mapping
- **T1547.001** – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

## Initial Triage Questions
1. What exact Run or RunOnce path was modified?
2. What executable or script path was written into the value?
3. Which process performed the modification?
4. Does the value point to a writable, temp, or unusual location?
5. Is the creating process an installer, updater, or suspicious binary?
6. Were there nearby file drops or scheduled task creation events?
7. Is the host expected to be receiving startup configuration changes?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `InitiatingProcessAccountName`
- `InitiatingProcessFileName`
- `RegistryKey`
- `RegistryValueData`

## Investigation Steps

### 1. Review the written value
- Identify the executable, script, or command stored in the Run key.
- Determine whether it points to:
  - `Program Files`
  - `System32`
  - `AppData`
  - `Temp`
  - `Users\Public`
  - `ProgramData`
- Writable-path references increase suspicion.

### 2. Validate the creating process
- Review the initiating process name and, if available, its path and signer.
- Determine whether it was:
  - a legitimate installer
  - enterprise configuration tooling
  - PowerShell or script host
  - suspicious or unknown binary

### 3. Correlate with supporting artifacts
Look for:
- recent file writes of the referenced binary
- scheduled task creation
- service creation
- browser download activity
- archive extraction
- defender tampering or other persistence changes

### 4. Review user and host context
- Confirm whether the host or user recently installed approved software.
- Determine whether the endpoint commonly receives startup policy changes.

### 5. Assess persistence likelihood
- Decide whether the Run key is:
  - expected software startup behavior
  - suspicious one-time installer residue
  - clear malicious autorun persistence

## Common Benign Explanations
- Legitimate software installers or updaters
- Authorized enterprise startup configuration changes :contentReference[oaicite:25]{index=25}

## Escalate When
Escalate if:
- the value points to a writable or suspicious path
- the creating process is unknown or user-driven
- the referenced binary was recently dropped
- the endpoint shows additional persistence or execution indicators
- the modification has no clear software-install context

## Suggested Response Actions
- Preserve the registry event and referenced path
- Review the referenced file on disk if present
- Remove unauthorized Run key values if compromise is confirmed
- Search for the same value or path across other endpoints
- Review associated file, process, and startup telemetry
- Isolate the host if the autorun entry is clearly malicious

## Analyst Notes
This is a foundational persistence analytic. It is most effective when analysts focus on the written value path and the identity of the process that made the change.