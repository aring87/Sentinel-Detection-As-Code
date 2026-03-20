# Suspicious Token Manipulation or SeDebug Use

## Goal
Identify command lines and tooling associated with token theft, impersonation, or privilege manipulation on Windows endpoints.

## Why This Alert Matters
Token abuse is a common privilege escalation technique. Attackers and offensive tools may use token duplication, impersonation, SeDebug privilege, or commands like `getsystem` to move from a lower-privileged context into a more powerful one.

## What the Detection Is Looking For
This detection looks for command-line references such as:
- `SeDebugPrivilege`
- `DuplicateToken`
- `CreateProcessWithTokenW`
- `Incognito`
- `getsystem`

## Likely ATT&CK Mapping
- T1134 – Access Token Manipulation
- T1068 – Exploitation for Privilege Escalation

## Initial Triage Questions
1. What tool or process referenced the token-manipulation strings?
2. Was the process launched from an expected admin, security, or lab context?
3. Did the process integrity level or token context change?
4. Was there nearby LSASS access, service abuse, or credential dumping behavior?
5. Is this host part of approved testing or red-team activity?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine
- InitiatingProcessFileName

## Investigation Steps
### 1. Identify the tool and ancestry
- Review the executable name and full command line.
- Determine whether the behavior came from:
  - offensive tooling
  - PowerShell
  - a custom binary
  - a security lab workflow
- Review parent and grandparent processes.

### 2. Assess privilege context
- Determine whether the process gained elevated rights, impersonated another token, or attempted to launch a new process with another token.
- Review whether the account should have had admin or debug rights on the host.

### 3. Correlate with adjacent high-risk activity
Check for:
- LSASS access
- service creation or service abuse
- credential dumping
- UAC bypass
- remote execution or lateral movement

### 4. Validate environment context
- Determine whether this is approved red-team, purple-team, or lab activity.
- Check maintenance windows, testing approvals, and known security tool usage.

## Common Benign Explanations
- Approved red-team or lab activity
- Security research or test tooling in a controlled environment

## Escalate When
Escalate if:
- the tool is unknown or suspicious
- the account should not be performing token operations
- LSASS or service abuse appears nearby
- the host is production and not part of testing
- there is evidence of follow-on SYSTEM or admin-level execution

## Suggested Response Actions
- preserve the full command line and process tree
- capture the tool or binary for analysis
- review integrity level changes and downstream processes
- check the same host for LSASS access or service-based execution
- notify IR if the behavior is unexplained or malicious

## Analyst Notes
This is your primary guide for token abuse and SeDebug-style privilege escalation. It is broad enough to catch several common offensive strings while still pointing the analyst toward validation of process ancestry and nearby credential or service abuse.