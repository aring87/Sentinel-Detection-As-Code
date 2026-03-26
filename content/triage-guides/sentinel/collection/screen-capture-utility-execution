# Suspicious Screen Capture Utility Execution Triage Guide

## Rule Overview

**Title:** Suspicious Screen Capture Utility Execution  
**Rule ID:** SENT-COLL-0003  
**Severity:** Medium  
**Risk Score:** 56  
**Tactic:** Collection  
**Technique:** T1113 - Screen Capture  
**Platform:** Microsoft Sentinel  
**Data Source:** DeviceProcessEvents  
**Lifecycle:** Experimental

## Purpose

This detection identifies screen capture utilities or scripted screenshot behavior that may indicate collection of user session data.

This matters because attackers may capture screenshots to collect:

- Credentials displayed on screen
- MFA prompts or codes
- Sensitive internal documents
- Remote session activity
- User workflows and visible data

## Detection Logic Summary

The rule looks for known screen capture utilities such as:

- `psr.exe`
- `nircmd.exe`
- `snippingtool.exe`
- `snipaste.exe`

It also looks for command lines containing:

- `screenshot`
- `capturedesktop`
- `saveimage`
- `screen capture`

The rule increases suspicion when:

- `nircmd.exe` or `snipaste.exe` are used
- the command line indicates explicit screenshot behavior
- the initiating process is a script host or LOLBin such as:
  - `powershell.exe`
  - `pwsh.exe`
  - `cmd.exe`
  - `wscript.exe`
  - `cscript.exe`
  - `mshta.exe`

The alert triggers when the suspicion score is 2 or greater.

## Likely Analyst Goal

Determine whether the screen capture behavior was:

- Normal user activity
- Help desk, documentation, or training activity
- Approved support tooling
- Suspicious collection of screen content

## Initial Triage Questions

1. Which utility executed?
2. Was the screenshot action interactive or scripted?
3. Is screen capture normal for the user and host?
4. Were image files saved to suspicious locations?
5. Did exfiltration, clipboard access, or archiving follow?

---

## Investigation Steps

### 1. Review the Process and Command Line

Inspect:

- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `AccountName`

Determine whether the activity involved:

- Built-in screenshot tooling
- Third-party capture utilities
- Explicit scripting of screenshot behavior

**Why this matters:**  
Scripted or automated screenshot behavior is generally more suspicious than ad hoc user screenshots.

---

### 2. Determine Whether the Activity Was Interactive or Scripted

Look for:

- Script hosts or LOLBins as parent processes
- Silent capture options
- Save paths in command lines
- Repeated or automated screenshot execution

**Why this matters:**  
Automated screen capture may indicate malware collecting visible session content.

---

### 3. Review Output File Locations

Check whether image files were written to:

- `%TEMP%`
- Downloads
- Desktop
- AppData
- Shared folders
- Staging directories

Determine whether screenshots were stored in:

- Expected user locations
- Hidden or temporary directories
- Folders associated with archive or exfiltration activity

**Why this matters:**  
Unusual save locations can indicate staging for transfer.

---

### 4. Determine Whether the Activity Is Expected

Validate whether the activity aligns to:

- Help desk support
- Documentation workflows
- User training
- Internal knowledge base creation
- Approved remote support tooling

**Why this matters:**  
Screen capture is common in support and training contexts.

---

### 5. Hunt for Related Collection Activity

Check for nearby:

- Clipboard access
- Browser credential access
- Archive creation
- File staging
- Email transfer
- Cloud upload
- Additional scripting activity

**Why this matters:**  
Screen capture paired with other collection activity is more concerning.

---

### 6. Assess User and Device Context

Review:

- Whether the host is high value
- Whether the user is privileged
- Whether the device has recent suspicious alerts
- Whether screen capture is typical for that role

**Why this matters:**  
Screen capture on sensitive systems can have higher impact.

---

## Benign Explanations

Common legitimate scenarios include:

1. Legitimate user screenshots
2. Support, documentation, or training workflows
3. Approved remote support tooling capturing user screens

---

## Suspicious Indicators

Escalate concern when you observe:

- Scripted or repeated screenshot capture
- Rare utilities such as `nircmd.exe`
- Execution from temp or suspicious paths
- Screenshots saved into staging folders
- Clipboard, credential, or exfiltration activity nearby
- Other malware indicators on the host

---

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- The activity aligns to user, help desk, or documentation workflows
- The utility and save path are expected
- No related suspicious behavior is present

### Escalate as Suspicious

Escalate when:

- Screen capture is uncommon for the host
- Activity appears scripted or automated
- Files are saved to suspicious locations
- Collection or transfer behavior is nearby

### Escalate as Likely Malicious

Escalate as likely malicious when:

- Evidence shows automated screen collection
- The activity is part of a broader attack chain
- Exfiltration or credential theft indicators are present

---

## Response Actions

Depending on findings, consider:

- Isolating the host if malicious collection is suspected
- Collecting the executed binary and command line artifacts
- Reviewing saved screenshots and staging paths
- Hunting for similar utilities across the environment
- Escalating to incident response if coordinated collection is confirmed

---

## Example Analyst Notes Template

### Analyst Summary

Alert fired for suspicious screen capture utility execution, potentially indicating collection of user session data or on-screen sensitive information.

### Key Findings

- **Affected device:**  
- **Affected user:**  
- **Utility executed:**  
- **Command line:**  
- **Initiating process:**  
- **Screenshot save path:**  
- **Expected business purpose:**  
- **Nearby collection or exfiltration activity:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious
