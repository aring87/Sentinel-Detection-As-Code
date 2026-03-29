# Triage Guide — PowerShell or LOLBin External Network Traffic

**Rule ID:** SENT-C2-0002  
**Severity:** High | **Risk Score:** 72  
**Lifecycle:** Experimental  
**Tactics:** Command and Control, Execution  
**Techniques:** T1105 — Ingress Tool Transfer, T1218 — System Binary Proxy Execution  

---

## What This Rule Detects

This rule fires when a known LOLBin — including `powershell.exe`, `pwsh.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `wscript.exe`, or `cscript.exe` — initiates an outbound network connection to a non-private, non-loopback IP address.

These binaries are frequently abused to download tooling, stage payloads, or beacon to command-and-control infrastructure. Legitimate use exists, but external connectivity from these processes is low-prevalence in most environments and warrants investigation.

---

## Immediate Triage Steps

### 1. Identify the process and destination

- What binary triggered the alert (`InitiatingProcessFileName`)?
- What is the full command line (`InitiatingProcessCommandLine`)?
- What is the remote IP, port, and URL (`RemoteIP`, `RemotePort`, `RemoteUrl`)?
- Is the destination a known-good service (e.g., Windows Update, vendor CDN) or an unknown/suspicious host?

### 2. Check the command line for indicators

Look for:

- Encoded or obfuscated commands (`-enc`, `-encodedcommand`, `FromBase64String`)
- Download cradles (`DownloadString`, `DownloadFile`, `iwr`, `iex`, `curl`, `Invoke-Expression`)
- References to temp or user-writable paths (`%TEMP%`, `AppData`, `ProgramData`, `Downloads`)
- URL patterns pointing to raw hosting (Pastebin, GitHub raw, IP-direct HTTP)

### 3. Review the parent process

- What spawned this process (`InitiatingProcessFileName`, `InitiatingProcessCommandLine`)?
- Is the parent a legitimate host (e.g., `explorer.exe`, `svchost.exe`) or something suspicious (e.g., `winword.exe`, `outlook.exe`, a browser, or another LOLBin)?
- Does the parent-child relationship make sense for the environment?

### 4. Evaluate execution context

- What account ran this process (`InitiatingProcessAccountName`)?
- Is it a user account, a service account, or SYSTEM?
- Is the device a workstation, server, or privileged host?
- Has this device or account been seen in other recent alerts?

### 5. Assess the remote destination

Run the remote IP through threat intelligence:

- Check `RemoteIP` in your TI sources (Defender TI, VirusTotal, Shodan, AbuseIPDB)
- Is the IP associated with known C2 infrastructure, bulletproof hosting, or an unexpected country?
- Is the port standard (80/443) or unusual?

---

## Escalation Criteria

Escalate to incident response if any of the following are true:

- The remote IP or domain is flagged as malicious in threat intelligence
- The command line contains download cradles, encoded content, or execution of a remote payload
- The parent process is a document application, browser, or another LOLBin
- The executing account is privileged or a service account
- Follow-on processes were spawned after the network connection

---

## Common False Positives

| Scenario | How to Confirm Benign |
|---|---|
| Approved automation retrieving external content | Validate against a known allowlist of admin scripts and scheduled tasks |
| Security tool or EDR contacting public services | Confirm process hash and signing cert match the vendor binary |
| Certificate retrieval workflows | Review URL — should match a known CA endpoint (e.g., `crl.microsoft.com`) |
| Software update via PowerShell | Confirm command matches a known update workflow; parent should be a service or task |

---

## Supporting KQL — Contextual Investigation

**Review all recent network events from the same device:**

```kql
DeviceNetworkEvents
| where DeviceName == "<DeviceName>"
| where Timestamp > ago(1h)
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp asc
```

**Look for download cradles in recent PowerShell on the same host:**

```kql
DeviceProcessEvents
| where DeviceName == "<DeviceName>"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","downloadstring","iex","iwr","irm","frombase64string","http://","https://")
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

**Check for child processes spawned after the network event:**

```kql
DeviceProcessEvents
| where DeviceName == "<DeviceName>"
| where Timestamp between (<AlertTime> .. <AlertTime> + 15m)
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by Timestamp asc
```

---

## Response Actions

| Action | When |
|---|---|
| Isolate the device | Remote IP is malicious or payload execution confirmed |
| Block remote IP/domain at firewall or proxy | Confirmed C2 or staging destination |
| Collect and preserve process memory | Active session suspected |
| Revoke session tokens and reset credentials | Compromised account suspected |
| Open incident and escalate | Any confirmed malicious indicator |

---

## ATT&CK Reference

| Technique | Description |
|---|---|
| T1105 | Ingress Tool Transfer — downloading remote tools or payloads |
| T1218 | System Binary Proxy Execution — abusing trusted Windows binaries |

---

*Owner: Detection Engineering | Last Modified: 2026-03-26*