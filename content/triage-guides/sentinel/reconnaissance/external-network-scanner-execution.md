# External Network Scanner Execution

## Goal
Identify execution of common network scanning tools on endpoints that may indicate internal or external reconnaissance activity.

## Why This Alert Matters
Network scanners are commonly used to identify live systems, open ports, exposed services, and reachable infrastructure. While these tools can be legitimate for vulnerability management, engineering, or lab work, they are also frequently used by attackers during internal discovery and pre-exploitation planning. This guide is based on a rule that detects execution of scanning tools such as `nmap.exe`, `masscan.exe`, `zmap.exe`, `advanced_ip_scanner.exe`, and `netscan.exe`. :contentReference[oaicite:6]{index=6}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for execution of:
- `nmap.exe`
- `masscan.exe`
- `zmap.exe`
- `advanced_ip_scanner.exe`
- `netscan.exe`

It surfaces the device, account, file name, command line, initiating process, file hash, and report ID. :contentReference[oaicite:7]{index=7}

## Likely ATT&CK Mapping
- **T1595** – Active Scanning

## Initial Triage Questions
1. Which scanning tool was executed?
2. Is the tool approved for the user, host, or subnet?
3. What targets, ranges, or ports were specified?
4. Was the scanner launched from a normal path or a writable or unusual location?
5. Is the host a sanctioned scanning system, lab asset, or standard endpoint?
6. Were there related DNS lookups, account discovery, or remote-execution attempts?
7. Did the same host later show exploitation, credential access, or lateral movement?

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

### 1. Identify the scanning tool and command
- Determine whether the process was:
  - `nmap`
  - `masscan`
  - `zmap`
  - GUI-based scanner
  - another renamed or staged scanner
- Review the command line for:
  - target IPs or ranges
  - port lists
  - scan type flags
  - timing or rate settings

### 2. Validate the source host
- Determine whether the host is:
  - an approved vulnerability scanner
  - security engineering workstation
  - lab system
  - normal endpoint
- Scanner execution on a normal user device is a stronger concern.

### 3. Review the execution path and signer
- Inspect whether the binary launched from:
  - standard program directories
  - removable media
  - `Temp`
  - `Downloads`
  - `AppData`
- Writable-path or unsigned scanner binaries increase suspicion.

### 4. Correlate with related reconnaissance
Look for:
- external lookup tool usage
- whoami/net/nltest/dsquery enumeration
- LDAP or AD discovery
- failed logon bursts
- suspicious remote-service sign-ins
- remote-execution attempts

### 5. Validate benign operational use
- Confirm whether the activity aligns with:
  - vulnerability management
  - engineering troubleshooting
  - sanctioned security assessment
  - lab validation
- If it does not, escalate.

## Common Benign Explanations
- Approved vulnerability management or security assessment activity
- Authorized network troubleshooting or engineering usage
- Internal security lab or validation hosts :contentReference[oaicite:8]{index=8}

## Escalate When
Escalate if:
- the tool is run from a standard endpoint or suspicious path
- the user is not expected to scan networks
- the target range includes sensitive or broad internal subnets
- the host also shows account discovery or remote-execution behavior
- the scan appears to be prep for exploitation or lateral movement

## Suggested Response Actions
- Preserve command-line and process telemetry
- Identify targets, ports, and scan scope
- Review whether the scanner binary is approved and signed
- Search for similar scanner execution elsewhere
- Investigate follow-on activity from the same host and user
- Contain the endpoint if malicious recon or staging is confirmed

## Analyst Notes
This is a high-value reconnaissance analytic because explicit scanner use is often easier to interpret than built-in discovery commands. The key discriminator is whether the tool and host are sanctioned for scanning.