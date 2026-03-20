# External Lookup Tool Usage

## Goal
Identify use of DNS and WHOIS lookup utilities that may be used for reconnaissance against external infrastructure, phishing preparation, or domain profiling.

## Why This Alert Matters
Utilities like `nslookup`, `whois`, and `dig` are legitimate admin tools, but they can also be used to profile external domains, review MX/TXT/NS/SOA records, and prepare phishing or infrastructure targeting. This is especially notable when used by non-admin users or in suspicious sequences.

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for:
- `nslookup.exe`
- `whois.exe`
- `dig.exe`

with command-line indicators such as:
- `-type=`
- `/querytype`
- `mx`
- `txt`
- `soa`
- `ns`

## Likely ATT&CK Mapping
- T1590 – Gather Victim Network Information
- T1596 – Search Open Technical Databases

## Initial Triage Questions
1. What domains were queried?
2. What record types were requested?
3. Is this normal for the user’s role?
4. Did the lookups align with phishing prep, target research, or troubleshooting?
5. Did scanning, phishing, or external auth activity happen nearby?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the lookup activity
- Review the exact utility and command line.
- Identify queried domains and requested record types.
- Determine whether the command focused on MX, TXT, SOA, or NS records.

### 2. Review user and host context
- Determine whether the user is part of:
  - network operations
  - email administration
  - security engineering
  - helpdesk
- Assess whether the host is appropriate for external lookup activity.

### 3. Correlate with surrounding behavior
Check for:
- suspicious email activity
- device-code phishing
- external scanning
- browser visits to related domains
- payload delivery or remote-service access

### 4. Assess intent
- Determine whether the queried domains belong to internal partners, public brands, or targets unrelated to the user’s duties.
- Review whether the lookups preceded phishing or spoofing-like activity.

## Common Benign Explanations
- DNS troubleshooting
- Email routing checks
- Helpdesk or network operations
- Security investigations

## Escalate When
Escalate if:
- the queried domains are unusual or sensitive
- the user role does not fit the activity
- the lookups precede phishing, spoofing, or scanning
- multiple recon alerts appear on the same host

## Suggested Response Actions
- preserve the full command line and queried domains
- validate whether the activity aligns with admin duties
- search for adjacent phishing, scanning, or external-auth telemetry
- hunt for similar lookup behavior on the same user or device

## Analyst Notes
This is a good low-severity recon guide that becomes much stronger when paired with scanner execution, phishing telemetry, or suspicious mailbox/auth behavior.