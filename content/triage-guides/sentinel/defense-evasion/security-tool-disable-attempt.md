# Triage Guide: Security Tool Disable Attempt

## Detection Title
Security Tool Disable Attempt

## Detection ID
SENT-DEFEV-0002

## Objective

This detection identifies attempts to stop security services or modify Microsoft Defender settings, exclusions, or service states through command-line activity.

## Why It Matters

Disabling security tooling is a common preparatory step before:
- malware deployment
- credential theft
- payload staging
- ransomware activity
- persistence installation

These behaviors often appear shortly before additional malicious actions.

## Alert Logic Summary

The rule looks for:
- `powershell.exe`
- `cmd.exe`
- `sc.exe`
- `net.exe`
- `reg.exe`

with command lines containing:
- `Set-MpPreference`
- `DisableRealtimeMonitoring`
- `Add-MpPreference`
- ` stop `
- ` config `
- ` WinDefend `
- ` Sense `

## Initial Triage Questions

- Which security service or setting was targeted?
- Was the action part of approved Defender maintenance?
- Which user and process initiated the command?
- Did the host show malware execution or staging afterward?
- Is the host normally managed by security tooling changes?

## Investigation Steps

1. Review the full command line and targeted setting/service.
2. Identify the user, parent process, and execution source.
3. Determine whether the activity aligns with approved maintenance.
4. Review immediate follow-on behavior:
   - downloads
   - script execution
   - file writes
   - persistence creation
   - outbound traffic
5. Check whether Defender exclusions or configuration changes were added.
6. Determine whether the same host has other defense-evasion indicators.

## Common False Positives

- planned security maintenance
- approved Defender policy changes
- lab testing
- troubleshooting by security administrators

## Escalation Guidance

Escalate when:
- the change is not tied to approved maintenance
- there is immediate follow-on malware-like behavior
- the actor is not an authorized security administrator
- multiple security-related services are targeted
- the activity occurs on a critical system or admin workstation

## Recommended Enrichment

- full command line
- targeted service/setting details
- initiating process and parent process
- maintenance window context
- recent downloads or staging events
- related alerts on the device
- host sensitivity and user role

## ATT&CK Mapping

- Defense Evasion
- T1562.001 – Impair Defenses

## Related Rule

- `detections/sentinel/defense-evasion/security-tool-disable-attempt.yml`