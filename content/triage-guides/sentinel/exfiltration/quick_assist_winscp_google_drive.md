# Quick Assist Followed by WinSCP or Google Drive Exfiltration Activity

## Goal
Identify likely vishing-driven intrusion chains where Quick Assist is followed by WinSCP execution or Google Drive access from the same device shortly after remote access.

## Why This Alert Matters
Attackers increasingly use social engineering and remote assistance tools to gain interactive access to endpoints without dropping obvious malware first. Once access is established, they may transfer data out using tools like WinSCP or upload through cloud services such as Google Drive. This guide is based on a detection that correlates Quick Assist execution with either WinSCP process activity or Google Drive network access within a short window on the same device. :contentReference[oaicite:30]{index=30}

## What the Detection Is Looking For
This detection correlates:
- `QuickAssist.exe` or `QuickAssistLauncher.exe`
- `WinSCP.exe` or `winscp.com`
- Google Drive-related network traffic such as:
  - `drive.google.com`
  - `docs.google.com`

The activity is considered suspicious when WinSCP execution or Google Drive access occurs shortly after Quick Assist starts on the same device. :contentReference[oaicite:31]{index=31}

## Likely ATT&CK Mapping
- **T1219** – Remote Access Software
- **T1105** – Ingress Tool Transfer
- **T1567.002** – Exfiltration to Cloud Storage

## Initial Triage Questions
1. Was the Quick Assist session approved and user-initiated?
2. Did WinSCP or Google Drive activity start shortly after the remote session began?
3. What data was transferred or likely transferred?
4. Was the user socially engineered into allowing remote access?
5. Was there preceding collection, archive creation, or credential access?
6. Is Quick Assist expected on this device?
7. Was the cloud or transfer destination approved?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `QAAccount`
- `QACommand`
- `FollowOnTime`
- `FollowOnType`
- `Evidence`

## Investigation Steps

### 1. Validate the Quick Assist session
- Confirm whether the user requested support.
- Determine whether the session was:
  - helpdesk-approved
  - unexpected
  - externally initiated
  - timed with social-engineering contact
- Review user reports, Teams/chat context, or support ticket references.

### 2. Review the follow-on transfer behavior
- If WinSCP was involved:
  - inspect command lines
  - review file-transfer destinations
  - check for archive or file staging beforehand
- If Google Drive was involved:
  - review the process and command line tied to the network access
  - determine whether browser or client-driven upload behavior occurred

### 3. Check for collection or staging before exfiltration
Look for:
- archive creation
- mass document access
- browser credential access
- clipboard collection
- cloud CLI use
- writable-path staging
- email exfiltration activity

### 4. Investigate social-engineering indicators
- Review whether the user interacted with:
  - helpdesk scam calls
  - fake support
  - Teams or email lures
  - suspicious browser sessions
- Quick Assist plus file transfer after user contact is high concern.

### 5. Validate legitimate admin workflows
- Determine whether the sequence fits:
  - sanctioned admin support
  - approved remote file transfer
  - helpdesk workflow
- If not, escalate rapidly.

## Common Benign Explanations
- Legitimate remote support followed by approved file transfer
- Help desk activity
- Sanctioned admin workflows using Quick Assist and cloud storage :contentReference[oaicite:32]{index=32}

## Escalate When
Escalate if:
- the user did not expect the Quick Assist session
- WinSCP or Google Drive activity followed immediately afterward
- sensitive data may have been staged or transferred
- the same device shows collection, archive creation, or credential-access behavior
- social-engineering indicators are present

## Suggested Response Actions
- Preserve Quick Assist, process, and network telemetry
- Validate the session with the end user
- Identify what files may have been transferred
- Review browser, archive, and staging activity on the endpoint
- Contain the host if malicious remote access and exfiltration are confirmed
- Search for the same sequence across other systems

## Analyst Notes
This is a high-value sequence analytic because it links remote access abuse directly to likely transfer behavior. It is especially important in environments where helpdesk scams or vishing are a realistic threat.