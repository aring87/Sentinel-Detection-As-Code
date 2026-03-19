# Triage Guide: PowerShell Script Dropped to Temp

## Detection Title
PowerShell Script Dropped to Temp

## Detection ID
SENT-EXEC-0003

## Objective

This detection identifies PowerShell creating script files in temporary directories such as user temp or Windows temp, which can indicate staging for execution.

## Why It Matters

PowerShell scripts written to temp paths can indicate:
- payload staging
- malware setup
- dropped admin or offensive scripts
- follow-on execution from user-writable directories

The normalized rule looks for `.ps1` or `.psm1` files written to temp paths by `powershell.exe` or `pwsh.exe`. :contentReference[oaicite:11]{index=11}

## Alert Logic Summary

The rule looks for:
- `DeviceFileEvents`
- folder paths including:
  - `AppData\Local\Temp`
  - `Windows\Temp`
- filenames ending in:
  - `.ps1`
  - `.psm1`
- initiating processes:
  - `powershell.exe`
  - `pwsh.exe` :contentReference[oaicite:12]{index=12}

## Initial Triage Questions

- What script name and temp path were used?
- Was the script later executed?
- Was the script part of an approved admin or packaging workflow?
- Did the script arrive from a download, email, or archive?
- What process chain led to the script drop?

## Investigation Steps

1. Review the full file path and filename.
2. Identify the initiating PowerShell process and user context.
3. Determine whether the script was later executed.
4. Review surrounding activity:
   - web downloads
   - archive extraction
   - Defender or SmartScreen events
   - persistence changes
5. Inspect whether the temp path is user-writable and suspicious for staging.
6. Correlate with network or process events near the file write time.

## Common False Positives

- temporary admin scripts written during troubleshooting
- software packaging or update workflows
- internal deployment tooling
- lab testing or development scripts :contentReference[oaicite:13]{index=13}

## Escalation Guidance

Escalate when:
- the script is executed soon after being written
- the filename or path is suspicious
- the host also shows downloads, persistence, or defense evasion
- the user context is unusual
- the activity cannot be tied to approved tooling

## Recommended Enrichment

- script path and filename
- initiating process command line
- user and host role
- later execution of the same file
- adjacent downloads or archive extraction
- persistence and registry changes
- network activity before and after the drop

## ATT&CK Mapping

- Execution
- T1059.001 – Command and Scripting Interpreter: PowerShell

## Related Rule

- `detections/sentinel/execution/powershell-script-dropped-to-temp.yml`