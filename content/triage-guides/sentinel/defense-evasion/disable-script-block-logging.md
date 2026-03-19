# Triage Guide: Disable Script Block Logging

## Detection Title
Disable Script Block Logging

## Detection ID
dodea-sig-028-disable-script-block-logging

## Objective

This detection identifies registry modifications that disable PowerShell Script Block Logging, reducing visibility into PowerShell execution.

## Why It Matters

PowerShell Script Block Logging is a high-value telemetry source for:
- encoded command visibility
- malicious script inspection
- post-exploitation activity review
- analyst triage

Disabling it can indicate deliberate defense evasion intended to conceal PowerShell abuse.

## Alert Logic Summary

The rule looks for:
- `DeviceRegistryEvents`
- registry keys containing `ScriptBlockLogging`
- `RegistryValueData =~ '0'`

This is intended to catch explicit disabling of logging through registry changes.

## Initial Triage Questions

- Which account changed the registry value?
- Was the host receiving a legitimate policy update?
- What process initiated the registry change?
- Was PowerShell used suspiciously afterward?
- Was this tied to approved administrative action?

## Investigation Steps

1. Review the affected registry path and value data.
2. Identify the initiating process and user account.
3. Determine whether the host recently received Group Policy or configuration changes.
4. Review nearby activity for:
   - encoded PowerShell
   - mshta/wscript activity
   - remote execution
   - security-tool modifications
5. Determine whether the change happened on one host or across many.
6. Confirm whether the action is part of approved testing or maintenance.

## Common False Positives

- lab or security validation
- legitimate policy changes in tightly controlled environments
- administrative logging reconfiguration

## Escalation Guidance

Escalate when:
- the initiating process is suspicious or unexpected
- the change is followed by PowerShell execution
- the user is not an approved admin
- the host is high-value
- the change is isolated and not part of a broader approved policy rollout

## Recommended Enrichment

- initiating process and parent process
- registry key/value details
- recent PowerShell events on the host
- GPO or policy-change context
- related LOLBin or network activity
- host role and ownership

## ATT&CK Mapping

- Defense Evasion
- T1562.002 – Impair Defenses: Disable Windows Event Logging / Logging Controls

## Related Rule

- `detections/sentinel/defense-evasion/disable-script-block-logging.yml`