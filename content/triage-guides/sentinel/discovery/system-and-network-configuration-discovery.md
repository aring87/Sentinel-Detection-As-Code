# System and Network Configuration Discovery

## Goal
Identify bursts of common host and network discovery commands that may indicate attacker reconnaissance on an endpoint.

## Why This Alert Matters
Attackers frequently run multiple built-in discovery commands in a short window to understand network layout, local interfaces, routing, host identity, and active connections. A burst of several configuration commands is often more meaningful than any single command on its own because it suggests systematic environment profiling rather than casual troubleshooting. This guide is based on a rule that looks for a burst of common host and network discovery commands within ten minutes. :contentReference[oaicite:12]{index=12}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for execution of commands such as:
- `ipconfig.exe`
- `arp.exe`
- `route.exe`
- `systeminfo.exe`
- `netstat.exe`
- `getmac.exe`
- `hostname.exe`

It summarizes commands by device and user within a 10-minute window and triggers when multiple such commands occur together. :contentReference[oaicite:13]{index=13}

## Likely ATT&CK Mapping
- **T1016** – System Network Configuration Discovery
- **T1082** – System Information Discovery
- **T1049** – System Network Connections Discovery

## Initial Triage Questions
1. How many discovery commands ran in the burst?
2. Which commands were used?
3. Is the host an admin workstation, server, or ordinary user system?
4. Is the user expected to perform host or network diagnostics?
5. Did the burst occur before lateral movement, credential access, or staging?
6. Were the commands run interactively or as part of a script?
7. Is this pattern normal for the device role?

## Key Fields To Review
- `DeviceName`
- `AccountName`
- `Timestamp`
- `CommandCount`
- `Commands`

## Investigation Steps

### 1. Review the command burst
- Inspect the full set of commands executed in the time window.
- Determine whether the burst focused on:
  - network interfaces
  - routes
  - active connections
  - host identity
  - MAC addresses
  - general system configuration

### 2. Assess host and user role
- Confirm whether the host is:
  - a workstation
  - server
  - jump box
  - admin or support asset
- Determine whether the user normally performs diagnostics.

### 3. Determine whether activity was scripted
- Check for parent process context and command sequencing.
- Decide whether the commands were:
  - typed manually
  - run from a batch file
  - run from PowerShell
  - launched by remote-access or management tooling

### 4. Correlate with adjacent activity
Look for:
- LDAP enumeration
- `net user`, `net group`, `whoami`, `nltest`
- failed authentication bursts
- remote scheduled task creation
- WMI or service-based remote execution
- archive creation
- outbound staging or exfiltration

### 5. Validate legitimate diagnostic context
- Confirm whether the event is tied to:
  - support troubleshooting
  - endpoint triage
  - inventory tooling
  - admin maintenance
- If the host is a standard user system, unexplained command bursts are more suspicious.

## Common Benign Explanations
- Troubleshooting by support teams
- Asset inventory or diagnostics tooling
- Administrator host triage :contentReference[oaicite:14]{index=14}

## Escalate When
Escalate if:
- the command burst occurs on a normal user workstation
- the same account also performs directory, trust, or account discovery
- the discovery is followed by credential access or remote execution
- the command sequence appears scripted or rapid
- the host shows persistence, staging, or exfiltration nearby

## Suggested Response Actions
- Preserve the command burst and surrounding process telemetry
- Review the same user and device for additional recon activity
- Correlate with authentication, persistence, and lateral-movement events
- Investigate whether the host was used as a staging point
- Suppress only when tied to clearly documented support or admin workflows

## Analyst Notes
This is a useful burst-style discovery analytic because it captures attacker behavior patterns rather than just single commands. It is strongest when combined with LDAP, account-discovery, or lateral-movement detections.