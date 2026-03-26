# Browser or Quick Assist Session Followed by Google Drive Exfiltration Utility

## Goal
Identify likely exfiltration behavior where a browser or Quick Assist session is followed by Google Drive upload activity or command-line tooling associated with cloud-based file transfer.

## Why This Alert Matters
Attackers increasingly use legitimate cloud services to move data because those services blend with normal business traffic and are often allowed through security controls. When cloud upload behavior happens immediately after remote support access or suspicious browser-driven activity, it may indicate data staging and exfiltration rather than ordinary productivity use.

## What the Detection Is Looking For
This detection reviews process and network telemetry for:
- parent processes such as:
  - `QuickAssist.exe`
  - `chrome.exe`
  - `msedge.exe`
  - `firefox.exe`
- child or related command lines referencing:
  - `drive.google.com`
  - `docs.google.com`
  - `upload`
  - `--drive`
  - `rclone`

## Likely ATT&CK Mapping
- T1567.002 – Exfiltration to Cloud Storage
- T1105 – Ingress Tool Transfer
- T1219 – Remote Access Software
- T1041 – Exfiltration Over C2 Channel or trusted service abuse context

## Initial Triage Questions
1. Did the Google Drive activity follow a remote support or suspicious browser session?
2. Which process initiated the traffic or command line?
3. Were sensitive files staged, archived, or uploaded during the same timeframe?
4. Does the affected user normally use Google Drive from this device?
5. Were there signs of discovery, file collection, or credential access before the upload?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- ParentImage or InitiatingProcessFileName
- CommandLine or InitiatingProcessCommandLine
- RemoteUrl
- file access or archive telemetry if available

## Investigation Steps
### 1. Validate the Google Drive signal
- Determine whether the alert came from:
  - browser traffic
  - a transfer utility
  - a script or CLI such as `rclone`
- Review the destination URL or command-line parameters.

### 2. Assess the preceding session
- Confirm whether the upload followed:
  - Quick Assist
  - browser-based social engineering
  - suspicious admin activity
- Establish a timeline from access to staging to upload.

### 3. Look for staging behavior
Check for:
- archive creation
- mass file access
- copies into temp or staging folders
- renaming prior to upload
- compression utilities
- sensitive file collection from shares or synced folders

### 4. Review user and asset context
- Determine whether the user normally uploads to Google Drive.
- Review whether the system is:
  - a finance workstation
  - executive device
  - admin workstation
  - shared VDI
- Prioritize systems with sensitive data access.

### 5. Validate business context
- Confirm whether the upload was part of:
  - approved collaboration
  - legitimate vendor sharing
  - remote support file exchange
- Check whether the exact destination, timing, and files match the claimed business need.

## Common Benign Explanations
- User collaboration using approved cloud storage
- Help desk or vendor support file transfer
- Developer upload of logs or diagnostics
- Authorized use of `rclone` or similar tooling

## Escalate When
Escalate if:
- the upload follows suspicious remote access or browser activity
- large or sensitive data sets were staged
- the user does not normally use Google Drive from that system
- the same actor showed discovery or credential access behavior first
- command-line tooling was used instead of ordinary browser interaction

## Suggested Response Actions
- preserve process, network, and file access evidence
- identify what files were likely uploaded
- review additional cloud-storage destinations used by the same device or user
- contain the host or suspend sessions if active exfiltration is suspected
- notify data owners if sensitive content may have been exposed

## Analyst Notes
Cloud-storage alerts become much more valuable when treated as part of a sequence. The strongest version is a timeline that shows suspicious access, file staging, and upload in one investigation.
