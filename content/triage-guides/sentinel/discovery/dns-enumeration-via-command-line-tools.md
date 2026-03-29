# DNS Enumeration via Command-Line Tools

## Goal
Identify use of command-line DNS and lookup utilities that may indicate environment discovery, domain enumeration, or early-stage reconnaissance.

## Why This Alert Matters
DNS and external lookup tools are commonly used during reconnaissance to gather information about infrastructure, domains, mail routing, name servers, and related services. While these tools are often legitimate for troubleshooting, they can also be used by attackers to map internal and external assets, verify targets, and prepare for later access or phishing activity. This guide is based on a rule that detects execution of `nslookup.exe`, `whois.exe`, and `dig.exe`. :contentReference[oaicite:0]{index=0}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for execution of:
- `nslookup.exe`
- `whois.exe`
- `dig.exe`

It focuses on use of these lookup utilities regardless of specific arguments, with the assumption that execution of these tools may represent host- or user-driven discovery activity. :contentReference[oaicite:1]{index=1}

## Likely ATT&CK Mapping
- **T1016** – System Network Configuration Discovery
- **T1046** – Network Service Discovery

## Initial Triage Questions
1. Which lookup tool was used?
2. What domains, IPs, or record types were queried?
3. Is the user or device expected to perform DNS or WHOIS lookups?
4. Did the activity occur on a workstation, admin system, or server?
5. Was this followed by additional AD, account, or trust discovery?
6. Is the tool installed normally on the device, or did it appear recently?
7. Did the same account later perform scanning, authentication abuse, or phishing-related activity?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `ReportId`

## Investigation Steps

### 1. Identify the lookup target
- Review the command line to determine:
  - queried domain
  - queried IP
  - record type
  - use of `whois` or public infrastructure lookup
- Pay attention to:
  - MX lookups
  - TXT lookups
  - SOA / NS lookups
  - repeated queries across many domains

### 2. Determine host and user context
- Identify whether the system is:
  - a normal user endpoint
  - helpdesk or admin workstation
  - network operations host
  - lab or engineering device
- Determine whether the user normally performs DNS diagnostics.

### 3. Review surrounding reconnaissance activity
Look for:
- AD enumeration
- `net.exe`, `whoami.exe`, `nltest.exe`, `dsquery.exe`
- LDAP or ADSI PowerShell queries
- network scanner execution
- external URL click spikes or suspicious domain interaction

### 4. Check for campaign development patterns
- Determine whether the domains queried are:
  - internal corporate assets
  - external vendor or partner domains
  - newly observed domains
  - suspicious or attacker-controlled infrastructure
- Look for repetition across multiple endpoints or users.

### 5. Validate legitimate use
- Confirm whether the event aligns with:
  - network troubleshooting
  - DNS diagnostics
  - helpdesk work
  - vulnerability or inventory scanning
- If yes, record the context for future tuning.

## Common Benign Explanations
- Administrator or network troubleshooting
- DNS diagnostics and support workflows
- Inventory or asset discovery tooling :contentReference[oaicite:2]{index=2}

## Escalate When
Escalate if:
- the queried infrastructure is sensitive, external, or newly observed
- the tool runs on a user workstation with no clear reason
- the same user performs LDAP, trust, or account enumeration nearby
- the activity is followed by phishing, scanning, or suspicious authentication
- `whois` or `dig` appears on a host where those tools are unusual

## Suggested Response Actions
- Preserve the process telemetry and command lines
- Identify queried domains and related infrastructure
- Search for the same queries on other systems
- Review the initiating account for other reconnaissance or initial-access activity
- Tune if clearly tied to normal operational diagnostics

## Analyst Notes
This is a lower- to medium-confidence reconnaissance signal on its own, but it becomes more valuable when correlated with LDAP, account enumeration, scanning tools, or suspicious external targeting behavior.