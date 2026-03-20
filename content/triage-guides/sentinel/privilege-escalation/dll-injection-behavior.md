# DLL Injection Behavior

## Goal
Identify process command lines that reference API patterns commonly associated with DLL injection and remote thread execution.

## Why This Alert Matters
DLL injection is a high-risk behavior that can be used for privilege escalation, defense evasion, credential theft, or execution inside trusted processes. Even though this rule is an older-style analytic, the behavior it targets is still important and distinct from the other privilege escalation rules in this batch.

## What the Detection Is Looking For
This detection looks for command-line references to:
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`

## Likely ATT&CK Mapping
- T1055.001 – Process Injection: Dynamic-link Library Injection

## Initial Triage Questions
1. What tool or binary referenced the injection-related APIs?
2. Was the process expected on this host?
3. What target process may have been involved?
4. Did the activity align with approved security testing or research?
5. Was there follow-on credential access, evasive behavior, or malicious child-process activity?

## Key Fields To Review
- TimeGenerated or Timestamp
- DeviceName
- FileName
- ProcessCommandLine

## Investigation Steps
### 1. Validate the process
- Identify the executable that referenced the API names.
- Determine whether the process is a known injector, offensive framework, debugger, or custom binary.
- Review signer, path, and reputation.

### 2. Assess likely target context
- Determine whether there are clues about the destination process in the command line or surrounding telemetry.
- Check whether protected or high-value processes were accessed nearby.

### 3. Correlate with adjacent suspicious behavior
Look for:
- token manipulation
- LSASS access
- service abuse
- reflective loading or in-memory execution
- suspicious network connections or persistence

### 4. Validate environment context
- Determine whether the host was part of red-team, malware analysis, or lab work.
- Check whether security tools or research utilities could explain the strings.

## Common Benign Explanations
- Approved red-team tooling
- Malware analysis or reverse engineering work
- Security research environments

## Escalate When
Escalate if:
- the process is unknown or untrusted
- the host is a production endpoint
- the same host shows token abuse, LSASS access, or service-based elevation
- there is evidence of stealthy or in-memory follow-on behavior

## Suggested Response Actions
- preserve the process command line and binary
- review memory- or injection-related telemetry if available
- check for target-process access and credential-theft indicators
- isolate the host if malicious execution is suspected
- hunt for the same binary or API strings across the environment

## Analyst Notes
Keep this guide for now even though it is older-style content. It covers a behavior family that is not duplicated by the other uploaded rules in this batch.