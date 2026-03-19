# Triage Guide: System and Network Configuration Discovery

## Detection Title
System and Network Configuration Discovery

## Objective

This detection identifies burst execution of host and network discovery commands used to gather local system, interface, routing, and connectivity information.

## Why It Matters

Attackers commonly run discovery commands to understand:
- system configuration
- IP addressing
- routes and interfaces
- active connections
- local host details
- environment topology

This behavior is especially meaningful when several commands are run together in a short window.

## Alert Logic Summary

The rule is intended to identify bursts of commands such as:
- `ipconfig`
- `arp`
- `route`
- `systeminfo`
- `netstat`
- `hostname`
- similar built-in discovery utilities

## Initial Triage Questions

- Which commands were run?
- Were they executed interactively or by script?
- Was the host under admin troubleshooting or a support session?
- Did the same user or host also perform account or AD discovery?
- Did the burst happen before remote access or staging activity?

## Investigation Steps

1. Review the command sequence and time window.
2. Identify the executing account and parent process.
3. Determine whether the host was being legitimately troubleshot.
4. Assess whether the discovery burst included:
   - system info
   - network config
   - route/interface discovery
   - connection inspection
5. Review adjacent activity for:
   - `net user`
   - LDAP / AD enumeration
   - PowerShell execution
   - LOLBin usage
   - outbound connections
6. Determine whether the behavior resembles a scripted recon sequence.

## Common False Positives

- administrator troubleshooting
- desktop support sessions
- system inventory scripts
- onboarding / baseline collection
- approved testing

## Escalation Guidance

Escalate when:
- multiple recon commands run in a short period from a non-admin system
- the activity is part of a broader discovery chain
- it is followed by execution, credential access, or movement
- the command burst is scripted or launched by suspicious parents
- the user cannot explain the activity

## Recommended Enrichment

- full command lines
- process tree
- user and host role
- neighboring discovery commands
- network activity after the discovery burst
- recent authentication events
- script host context if PowerShell/cmd was used

## ATT&CK Mapping

- Discovery
- T1016 – System Network Configuration Discovery
- T1082 – System Information Discovery
- T1049 – System Network Connections Discovery

## Related Rule

- `detections/sentinel/discovery/system-and-network-configuration-discovery.yml`