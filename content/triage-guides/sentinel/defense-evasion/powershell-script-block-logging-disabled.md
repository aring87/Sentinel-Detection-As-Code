# Triage Guide: PowerShell Script Block Logging Disabled

## Detection Title
PowerShell Script Block Logging Disabled

## Detection ID
SENT-DEFEV-0001

## Objective

This detection identifies registry changes that disable or weaken PowerShell logging controls, including Script Block Logging and Transcription settings.

## Why It Matters

PowerShell logging controls are critical for visibility into:
- malicious script execution
- encoded commands
- tool transfer and staging
- post-exploitation automation

Attackers may disable these settings before executing PowerShell-heavy activity in order to reduce auditability.

## Alert Logic Summary

The rule looks for:
- `DeviceRegistryEvents`
- registry keys related to:
  - `ScriptBlockLogging`
  - `Transcription`
- actions such as:
  - `RegistryValueSet`
  - `RegistryKeyCreated`

It projects the initiating process and account for triage.

## Initial Triage Questions

- Which logging control was changed?
- Was the initiating process expected?
- Did the host receive a legitimate policy or baseline update?
- Was suspicious PowerShell or LOLBin activity observed afterward?
- Is the account authorized to make this change?

## Investigation Steps

1. Review the exact registry key, value name, and data.
2. Identify the initiating process, user, and parent process.
3. Determine whether the system was receiving expected policy changes.
4. Review for suspicious follow-on activity:
   - PowerShell execution
   - encoded commands
   - mshta/wscript/pwsh usage
   - external downloads
5. Check for additional defense-evasion changes on the host.
6. Determine whether the activity affected one machine or many.

## Common False Positives

- Group Policy changes from approved admin workflows
- controlled security testing
- baseline or logging reconfiguration approved by engineering

## Escalation Guidance

Escalate when:
- the change is not clearly tied to approved policy updates
- PowerShell or LOLBin activity follows the modification
- the initiating process is suspicious or user-writable
- the affected host is privileged or sensitive
- multiple security settings are altered together

## Recommended Enrichment

- registry path and values
- initiating process path and signer
- parent and child processes
- GPO/policy rollout context
- recent PowerShell activity
- recent network or file staging events
- host criticality

## ATT&CK Mapping

- Defense Evasion
- T1562.001 – Impair Defenses

## Related Rule

- `detections/sentinel/defense-evasion/powershell-script-block-logging-disabled.yml`