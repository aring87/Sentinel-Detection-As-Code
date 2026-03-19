# Triage Guide: PowerShell Encoded Command Execution

## Detection Title
PowerShell Encoded Command Execution

## Detection ID
SENT-EXEC-0001

## Objective

This detection identifies PowerShell or PowerShell Core execution using encoded command arguments such as `-enc` or `-encodedcommand`, and attempts to decode the Base64 payload for analyst review.

## Why It Matters

Encoded PowerShell is commonly used to:
- hide malicious script content
- evade casual review of command lines
- stage or launch payloads
- download or execute follow-on content
- perform credential theft, persistence, or lateral movement

While encoded commands can be legitimate, they are high-value for triage because they often represent intentional obfuscation. The normalized rule projects the encoded and decoded content for review. :contentReference[oaicite:6]{index=6}

## Alert Logic Summary

The rule looks for:
- `powershell.exe`
- `pwsh.exe`

with command lines containing:
- `-enc`
- `-encodedcommand`

It extracts the Base64 argument and attempts to decode it for analyst review. :contentReference[oaicite:7]{index=7}

## Initial Triage Questions

- What does the decoded command actually do?
- Was the command launched by an approved admin script or software deployment tool?
- What parent process launched PowerShell?
- Did the same device show related file, registry, or network activity?
- Is the user account expected to run encoded PowerShell?

## Investigation Steps

1. Review the full command line and decoded payload.
2. Identify the user, device, and parent process context.
3. Determine whether the decoded content includes:
   - downloads
   - credential access
   - persistence creation
   - remote execution
   - execution from temp or user-writable paths
4. Review surrounding events on the host:
   - file writes
   - registry changes
   - network connections
   - service or scheduled task creation
5. Validate whether the execution aligns with approved administrative automation.

## Common False Positives

- approved administrative automation using encoded PowerShell
- software deployment tooling
- enterprise configuration scripts
- red team or lab validation activity

## Escalation Guidance

Escalate when:
- the decoded payload is suspicious or clearly malicious
- the parent process is unusual
- the account or device context is abnormal
- the execution is followed by downloads, persistence, or credential access
- the activity cannot be tied to approved automation

## Recommended Enrichment

- decoded command content
- full process tree
- parent and child processes
- user privilege level
- recent file writes
- recent registry modifications
- outbound connections near execution time

## ATT&CK Mapping

- Execution
- T1059.001 – Command and Scripting Interpreter: PowerShell

## Related Rule

- `detections/sentinel/execution/powershell-encoded-command-execution.yml`