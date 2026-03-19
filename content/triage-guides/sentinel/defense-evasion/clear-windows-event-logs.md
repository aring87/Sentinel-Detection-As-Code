# Triage Guide: Clear Windows Event Logs

## Detection Title
Clear Windows Event Logs

## Detection ID
SENT-DEFEV-0003

## Objective

This detection identifies commands used to clear Windows event logs, which may indicate an attempt to remove forensic evidence and reduce visibility into malicious activity.

## Why It Matters

Clearing event logs is a common defense-evasion technique used to:
- erase evidence of execution
- hide persistence or lateral movement activity
- disrupt incident reconstruction
- reduce the effectiveness of detection and response

This behavior is especially concerning when it occurs after suspicious execution, privilege escalation, or credential access events.

## Alert Logic Summary

The rule looks for:
- `wevtutil.exe`
- `powershell.exe`
- `cmd.exe`

with command lines containing:
- ` cl `
- `Clear-EventLog`
- `Remove-EventLog`

## Initial Triage Questions

- Which logs were targeted for clearing?
- Who executed the command?
- Was the user an approved administrator?
- Did the activity occur during an expected maintenance window?
- Was there suspicious activity shortly before the clear command?

## Investigation Steps

1. Review the full process command line.
2. Identify the executing account and privilege context.
3. Determine which log or logs were targeted.
4. Review the parent process and surrounding execution chain.
5. Look for suspicious activity immediately before the log-clearing event:
   - PowerShell
   - LOLBins
   - credential access
   - persistence creation
   - remote execution
6. Confirm whether the action aligns with approved admin or lab activity.

## Common False Positives

- rare administrative log maintenance
- lab validation or training exercises
- incident-response cleanup in controlled environments

## Escalation Guidance

Escalate when:
- the command is not part of approved administration
- the activity follows suspicious execution or credential access
- the actor is not recognized as an authorized admin
- multiple logs are cleared in quick succession
- the host is high-value or otherwise sensitive

## Recommended Enrichment

- full command line
- parent and child processes
- user privilege level
- recent alerts on the same host
- remote access activity on the device
- timeline of suspicious activity before the log clear

## ATT&CK Mapping

- Defense Evasion
- T1070.001 – Indicator Removal on Host: Clear Windows Event Logs

## Related Rule

- `detections/sentinel/defense-evasion/clear-windows-event-logs.yml`