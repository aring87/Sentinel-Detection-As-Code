# Triage Guide: PowerShell Encoded Command from Temp Folder

## Detection Title
PowerShell Encoded Command from Temp Folder

## Detection ID
SENT-EXEC-0004

## Objective

This detection identifies PowerShell encoded-command execution where the parent, script path, or surrounding activity suggests execution from a temporary directory or other staging location.

## Why It Matters

Encoded PowerShell from temp-like paths is more suspicious than encoded PowerShell alone because it suggests:
- staged malware execution
- user-writable path abuse
- unpacked or downloaded payload execution
- short-lived script launchers

This is useful as a higher-context sibling to the broader encoded-command rule.

## Alert Logic Summary

The rule is intended to identify encoded PowerShell execution associated with temp or staging paths. Review the final YAML to confirm the exact path conditions and process fields being used.

## Initial Triage Questions

- Did the script or binary execute from temp or another user-writable path?
- Was the encoded command decoded successfully?
- Was the file recently downloaded or extracted?
- What launched the encoded PowerShell?
- Is the host exhibiting multiple attacker behaviors?

## Investigation Steps

1. Review the full command line and decoded payload.
2. Identify the execution path, parent process, and user context.
3. Determine whether the file or script originated from:
   - browser download
   - archive extraction
   - email attachment
   - temp staging
4. Review surrounding process, file, and network events.
5. Check for persistence or credential access after execution.
6. Determine whether the behavior matches known deployment or admin workflows.

## Common False Positives

- approved admin scripts staged temporarily
- software deployment tooling
- packaging workflows using temp extraction paths

## Escalation Guidance

Escalate when:
- the decoded content is suspicious
- the path is user-writable and abnormal
- the activity is paired with downloads or staging
- the parent process is suspicious
- there are related defense-evasion or persistence events

## Recommended Enrichment

- decoded command
- temp path details
- parent and child processes
- download source if present
- archive or extraction events
- registry and persistence activity
- network connections near execution time

## ATT&CK Mapping

- Execution
- T1059.001 – Command and Scripting Interpreter: PowerShell

## Related Rule

- `detections/sentinel/execution/powershell-encoded-command-from-temp-folder.yml`