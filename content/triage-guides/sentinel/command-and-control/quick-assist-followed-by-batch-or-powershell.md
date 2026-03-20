# Quick Assist Followed by Batch or PowerShell Execution

## Goal
Identify suspicious use of Quick Assist followed by batch or PowerShell execution, which may indicate social-engineering-driven remote access abuse.

## Why This Alert Matters
Quick Assist is a legitimate Microsoft support tool, but it is increasingly abused by attackers posing as helpdesk or IT support. Script execution after the session starts is a strong sign that the session may be malicious.

## What the Detection Is Looking For
This detection looks for:
- Quick Assist execution
- followed by batch script or PowerShell activity
- with suspicious command-line indicators

## Initial Triage Questions
1. Did the user request support?
2. Was Quick Assist approved or expected?
3. What script or batch file executed afterward?
4. Did the session lead to downloads, persistence, or credential abuse?

## Key Evidence To Review
- Quick Assist process start
- follow-on script command lines
- helpdesk records
- downloaded files
- persistence and remote tool activity

## Investigation Steps
1. Confirm whether the Quick Assist session was legitimate.
2. Review the batch or PowerShell command launched after the session.
3. Determine whether the command downloaded content or altered the system.
4. Check for RMM installation, persistence, or credential access after the session.
5. Validate the user story and whether the operator claimed to be support.

## Common Benign Explanations
- legitimate IT remediation
- approved remote support
- scripted support diagnostics

## Escalate When
Escalate if:
- the user did not request help
- the script is suspicious or obfuscated
- malicious downloads or persistence follow
- the activity aligns with known social-engineering patterns

## Suggested Response Actions
- terminate the session
- isolate the endpoint if compromise is suspected
- preserve scripts and command lines
- review other endpoints for similar Quick Assist chains

## Analyst Notes
This should be treated seriously when Quick Assist is not common in your environment.