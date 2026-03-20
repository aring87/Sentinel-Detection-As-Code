# Registry Run Key Modification

## Goal
Identify creation or modification of autorun registry keys that can be used to establish persistence at user logon or system startup.

## Why This Alert Matters
Run and RunOnce keys are a classic persistence location. Malware, unwanted software, and hands-on-keyboard attackers often place executables, scripts, or LOLBins in these keys so code runs automatically when a user logs in or the system starts. The standardized rule looks for common autorun paths and captures both value sets and key creation, which makes it broader than the older versions. 

## What the Detection Is Looking For
This detection reviews `DeviceRegistryEvents` for:
- registry paths containing:
  - `\Software\Microsoft\Windows\CurrentVersion\Run`
  - `\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
- actions such as:
  - `RegistryValueSet`
  - `RegistryKeyCreated`

## Likely ATT&CK Mapping
- T1547.001 – Registry Run Keys / Startup Folder

## Initial Triage Questions
1. What value was written and what executable or script path does it reference?
2. Which process and account wrote the registry value?
3. Is the referenced path expected, signed, and located in a trusted directory?
4. Was this part of a legitimate install, update, or enterprise configuration change?
5. Did the same host also show scheduled task creation, service hijack, or suspicious file drops?

## Key Fields To Review
- Timestamp
- DeviceName
- InitiatingProcessAccountName
- InitiatingProcessFileName
- RegistryKey
- RegistryValueData

## Investigation Steps
### 1. Validate the registry modification
- Confirm the exact Run or RunOnce key path.
- Identify the value data and determine what will execute at logon or startup.
- Check whether the referenced path points to:
  - `AppData`
  - `Temp`
  - `ProgramData`
  - user-writable folders
  - scripts or LOLBins

### 2. Review the writing process
- Determine what process made the registry change.
- Assess whether it was a known installer, updater, admin script, or an unexpected process.
- Review parent/child process context if available.

### 3. Inspect the referenced payload
- Determine whether the referenced binary or script exists on disk.
- Review signer, hash reputation, path, and creation time.
- Check whether the payload was recently dropped before the registry modification.

### 4. Correlate with related persistence or execution
Look for:
- suspicious scheduled task creation
- service creation or service path changes
- PowerShell or script execution
- startup folder writes
- user logon followed by immediate payload execution

### 5. Validate business context
- Check for recent software installs, upgrades, or enterprise deployment activity.
- Determine whether the account or software normally writes autorun keys.

## Common Benign Explanations
- Legitimate software installers or updaters
- Authorized enterprise startup configuration changes
- Admin packaging or deployment activity

## Escalate When
Escalate if:
- the value points to a suspicious or user-writable path
- the writing process is unusual or malicious-looking
- the user or admin cannot explain the change
- the same host has multiple persistence indicators
- the payload is unsigned, newly dropped, or clearly malicious

## Suggested Response Actions
- preserve the written registry value and payload path
- collect the referenced binary or script for analysis
- review the initiating process tree
- remove or disable the autorun entry if confirmed malicious
- search for the same value or payload across the environment

## Analyst Notes
Prefer this guide as the canonical Run key persistence workflow because it is broader and more standardized than the older variants. The older `dodea-sig-007` version only looked at a smaller set of keys and the `dodea-sig-026` version was narrower still because it relied on specific value names like `Updater` or `ServiceHost`. 