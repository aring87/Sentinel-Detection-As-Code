# Node.js Installer or GUID-Named App Followed by Scheduled Task Persistence

## Goal
Identify suspicious installer or Node.js/Electron-style application execution followed by scheduled task persistence.

## Why This Alert Matters
Some malware and fake-software campaigns masquerade as legitimate installers, Electron apps, or utility packages and then establish persistence through scheduled tasks. This is especially relevant for SEO-poisoned downloads, freeware impersonation, and utility installers that hide a malicious follow-on action. This guide is based on a rule that correlates suspicious installer execution with scheduled task creation within one hour on the same device. :contentReference[oaicite:17]{index=17}

## What the Detection Is Looking For
This detection correlates:
- suspicious installation-like execution involving:
  - `node.exe`
  - `msiexec.exe`
  - `setup.exe`
  - `install.exe`
  - GUID-like command-line patterns
- follow-on persistence activity involving:
  - `schtasks.exe`
  - PowerShell scheduled-task commands

The activity is considered suspicious when task creation occurs within about an hour of the initial install-like event. :contentReference[oaicite:18]{index=18}

## Likely ATT&CK Mapping
- **T1053.005** – Scheduled Task/Job: Scheduled Task
- **T1204** – User Execution

## Initial Triage Questions
1. What installer or setup activity occurred first?
2. Was the software package approved, signed, and expected?
3. Did the command line or package name look random, generic, or masqueraded?
4. What scheduled task was created afterward?
5. Did the software come from a suspicious website or SEO-poisoned lure?
6. Was the host a standard user endpoint or developer system?
7. Did the install also drop files into AppData, ProgramData, or roaming paths?

## Key Fields To Review
- `DeviceName`
- `InitiatingProcessAccountName`
- `InstallTime`
- `InstallCmd`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `PersistTime`
- `PersistProc`
- `PersistCmd`

## Investigation Steps

### 1. Review the installer or setup event
- Determine whether the initial process was:
  - a normal installer
  - `node.exe`
  - a GUID-style launcher
  - a generic `setup.exe` or `install.exe`
- Review signer, file path, and source URL if available.

### 2. Inspect the scheduled task
- Identify the task name, trigger, action, and run context.
- Determine whether the task launches:
  - a suspicious binary
  - a script interpreter
  - a writable-path executable
  - a masqueraded updater

### 3. Check software source and delivery
- Review whether the app was:
  - downloaded from an unusual domain
  - delivered through SEO-poisoning
  - presented as freeware or a productivity utility
  - recently introduced to the environment

### 4. Correlate with related persistence or malware behavior
Look for:
- AppData or ProgramData drops
- Rundll32 or script host execution
- Defender tampering
- browser-lure activity
- external network traffic
- archive creation or exfiltration

### 5. Validate benign installation context
- Determine whether the software is:
  - enterprise-approved
  - a normal Electron/Node app
  - part of sanctioned deployment
- Legitimate installers can create tasks, so approval context matters.

## Common Benign Explanations
- Legitimate installers that register scheduled tasks
- Approved Electron or Node.js application setups
- Enterprise software deployment :contentReference[oaicite:19]{index=19}

## Escalate When
Escalate if:
- the software is unapproved or suspiciously sourced
- the installer name or command line looks generic or GUID-heavy
- the scheduled task launches from a writable or odd path
- the device also shows suspicious downloads, scripts, or loader behavior
- the user is not expected to install this type of software

## Suggested Response Actions
- Preserve the installer and task-creation telemetry
- Review task details directly on the endpoint
- Identify download source and signer information
- Search for the same installer or task pattern across other hosts
- Isolate the endpoint if malicious software masquerading is confirmed
- Coordinate with software-approval or IR teams as needed

## Analyst Notes
This is a useful persistence sequence analytic because it links user-execution or installer behavior to a concrete persistence mechanism. It is especially valuable for fake software and SEO-poisoning investigations.