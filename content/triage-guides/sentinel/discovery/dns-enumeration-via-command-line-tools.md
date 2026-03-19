# Triage Guide: DNS Enumeration via Command-Line Tools

## Detection Title
DNS Enumeration via Command-Line Tools

## Objective

This detection identifies execution of command-line utilities commonly used to perform DNS-based enumeration and external lookup activity. These tools may be used to discover hosts, domains, name servers, or public-facing infrastructure.

## Why It Matters

Attackers often use DNS utilities early in an intrusion to:
- resolve internal or external hosts
- identify name servers
- gather domain information
- validate command-and-control infrastructure
- map reachable services or systems

This behavior is not inherently malicious, but it becomes more concerning when used from unusual hosts, by unusual users, or alongside other discovery or staging activity.

## Alert Logic Summary

The rule is intended to identify use of command-line DNS enumeration tooling such as:
- `nslookup`
- `dig`
- `host`
- `whois`

depending on the exact detection logic in the paired rule.

## Initial Triage Questions

- Which tool was used?
- Who executed it?
- Was the execution on a user workstation, admin host, server, or test box?
- Was the target internal or external?
- Is this expected for the user’s role?
- Did the same user or host also perform other discovery actions?

## Investigation Steps

1. Review the full process command line.
2. Identify the executing account and host role.
3. Determine which domains, hosts, or IPs were being queried.
4. Assess whether the tool usage was:
   - normal troubleshooting
   - administrator activity
   - security testing
   - broad reconnaissance
5. Look for related discovery activity on the same device:
   - `ipconfig`
   - `arp`
   - `net`
   - `nltest`
   - `dsquery`
   - `systeminfo`
6. Review whether the activity is followed by:
   - remote access attempts
   - outbound connections
   - PowerShell execution
   - suspicious downloads

## Common False Positives

- administrator troubleshooting
- network diagnostics
- help desk activity
- server configuration checks
- approved security or infrastructure testing

## Escalation Guidance

Escalate when:
- the user is not expected to perform network enumeration
- the host is a normal user workstation
- the same system shows other discovery or execution behaviors
- the queries target suspicious or attacker-controlled domains
- the activity appears broad, repeated, or scripted

## Recommended Enrichment

- full command line
- queried domains or IPs
- process tree
- user role
- host criticality
- recent discovery commands on the same host
- recent outbound connections

## ATT&CK Mapping

- Discovery
- T1016 – System Network Configuration Discovery
- T1590 / T1596 style pre-attack or recon behaviors, depending on exact usage context

## Related Rule

- `detections/sentinel/discovery/dns-enumeration-via-command-line-tools.yml`