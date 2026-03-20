# External Network Scanner Execution

## Goal
Identify execution of common network scanning tools on Windows endpoints that may indicate reconnaissance against internal or external infrastructure.

## Why This Alert Matters
Network scanners are frequently used to discover live systems, open ports, and exposed services before exploitation or lateral movement. While some teams legitimately use these tools, their presence on general user endpoints or unexpected servers is often suspicious.

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for execution of tools such as:
- `nmap.exe`
- `masscan.exe`
- `zmap.exe`
- `advanced_ip_scanner.exe`
- `netscan.exe`

## Likely ATT&CK Mapping
- T1595 – Active Scanning

## Initial Triage Questions
1. Is the scanning tool approved for this host and user?
2. What targets or ranges were likely scanned?
3. Was this on a security, engineering, or admin system where scanning is expected?
4. Did the scan precede exploitation, lateral movement, or remote access activity?
5. Is this a sanctioned assessment, lab action, or unexpected recon?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine
- InitiatingProcessFileName

## Investigation Steps
### 1. Validate the scanner execution
- Confirm the exact tool that launched.
- Review the full command line for:
  - target hosts or ranges
  - scan type
  - port lists
  - timing or stealth options
- Determine whether the tool was launched interactively or by another process.

### 2. Review host and user context
- Determine whether the host is:
  - a security scanning node
  - admin workstation
  - standard user endpoint
  - server or jump box
- Determine whether the user is authorized to run network scanners.

### 3. Correlate with network activity
- Review nearby outbound connections or scan-like traffic.
- Check whether the process was followed by:
  - remote service sign-ins
  - lateral movement
  - exploitation attempts
  - file transfer or payload delivery

### 4. Assess adjacent execution context
- Review parent process lineage.
- Check whether the scanner was launched from a script, temp folder, archive extraction path, or remote session.

## Common Benign Explanations
- Approved vulnerability scanning
- Security assessments
- Network engineering troubleshooting
- Lab activity

## Escalate When
Escalate if:
- the host or user is not expected to run scanners
- targets include sensitive internal systems
- the scanner launched from a suspicious path or parent process
- other recon or lateral movement activity followed
- the activity is unexplained by approved operations

## Suggested Response Actions
- preserve the full command line and binary path
- identify likely targets and scanning scope
- validate whether the host is an approved scanning system
- review follow-on auth, remote access, or exploitation telemetry
- notify IR if the activity appears unauthorized

## Analyst Notes
Use this as the canonical scanner-execution guide. It is broader and more standardized than the older active-scanning rule because it keys on direct process execution of several common scanners instead of relying mainly on network-event correlation.