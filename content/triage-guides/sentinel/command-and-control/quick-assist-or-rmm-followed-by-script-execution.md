# Quick Assist or RMM Followed by Script Execution

## Goal
Identify remote-support or RMM sessions that are followed closely by suspicious script execution, which may indicate social-engineering-driven intrusion activity.

## Why This Alert Matters
Attackers increasingly abuse legitimate remote assistance and RMM tools because they provide interactive access while appearing benign. If Quick Assist or a common RMM tool is followed closely by PowerShell, CMD, MSHTA, or other script execution, that can indicate a help-desk scam, vishing campaign, hands-on-keyboard intrusion, or post-access staging.

## What the Detection Is Looking For
This detection looks for execution of Quick Assist or common RMM tools, followed within a short time window by suspicious script or command execution.

RMM or remote support processes may include:
- `quickassist.exe`
- `anydesk.exe`
- `teamviewer.exe`
- `screenconnect.clientservice.exe`
- `screenconnect.windowsclient.exe`
- `simplehelp.exe`
- `netsupportmanager.exe`
- `logmeinrescue.exe`
- `pdqconnectagent.exe`
- `ateraagent.exe`
- `itagent.exe`

Script or execution follow-on processes may include:
- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`
- `rundll32.exe`

The detection is especially interested in suspicious command-line content such as:
- `-enc`
- `downloadstring`
- `curl`
- `iwr`
- `irm`
- `iex`
- `frombase64string`
- URLs
- `.bat`
- `.cmd`

## Likely ATT&CK Mapping
- **T1219** – Remote Access Software
- **T1059** – Command and Scripting Interpreter

## Initial Triage Questions
1. Was the remote-support session expected and approved?
2. Which RMM or remote-support tool was used?
3. How soon after the remote session did the scripting activity begin?
4. What script interpreter or LOLBin was launched?
5. Does the command line indicate download, staging, decoding, or execution?
6. Did the user request support, or is there evidence of social engineering?
7. Was there follow-on persistence, credential theft, or exfiltration?

## Key Fields To Review
- `DeviceName`
- `RMMTime`
- `RMMUser`
- `RMMProcess`
- `RMMCmd`
- `ScriptTime`
- `ScriptUser`
- `ScriptProcess`
- `ScriptCmd`

## Investigation Steps

### 1. Confirm the remote access tool
- Identify which remote-support or RMM process triggered the detection.
- Determine whether the tool is:
  - approved
  - unmanaged
  - newly observed
  - commonly abused in your environment

### 2. Review the follow-on scripting behavior
- Inspect the command line for:
  - encoded commands
  - remote downloads
  - script retrieval
  - batch execution
  - LOLBin abuse
- Determine whether the scripting activity began immediately after session initiation.

### 3. Validate user context
- Review whether the user:
  - opened a help-desk request
  - interacted with external support
  - was contacted unexpectedly
  - showed signs of being socially engineered
- Check for related Teams, phone-based, or email lure activity.

### 4. Check for post-access actions
Look for:
- persistence creation
- browser credential access
- PowerShell external network traffic
- archive creation
- cloud uploads
- WinSCP or file-transfer activity
- mailbox or identity abuse

### 5. Validate administrative legitimacy
- Confirm whether the account and host normally use the RMM tool.
- Check whether the parent-child sequence aligns with known IT workflows.
- Review maintenance windows, support tickets, or change records.

## Common Benign Explanations
- Approved remote support sessions
- Helpdesk or infrastructure administration
- IT automation during sanctioned support workflows
- Enterprise RMM maintenance activity

## Escalate When
Escalate if:
- the user did not request support
- the tool is unmanaged or unusual for the host
- script execution begins shortly after remote access starts
- the command line indicates download, staging, or payload execution
- there is follow-on persistence, credential theft, or exfiltration
- the same user also shows phishing or social-engineering indicators

## Suggested Response Actions
- Preserve RMM and script process telemetry
- Validate with the user whether the support session was legitimate
- Contain the host if unauthorized remote access is confirmed
- Review all activity performed during and shortly after the session
- Search for the same RMM tool or script chain across other endpoints
- Block or monitor suspicious RMM tooling if not approved

## Analyst Notes
This is one of the stronger modern intrusion-sequence detections because it ties legitimate remote-access tooling to suspicious execution behavior. It is especially valuable in environments where help-desk scams, vishing, or external support fraud are realistic threats.