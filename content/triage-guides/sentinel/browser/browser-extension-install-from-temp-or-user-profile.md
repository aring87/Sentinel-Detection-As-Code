# Browser Extension Files Created by Non-Browser Process Triage Guide

## Rule Overview

**Title:** Browser Extension Files Created by Non-Browser Process  
**Rule ID:** SENT-BROW-0001  
**Severity:** Medium  
**Risk Score:** 60  
**Tactic:** Persistence  
**Technique:** T1176 - Browser Extensions  
**Platform:** Microsoft Sentinel  
**Data Source:** DeviceFileEvents  
**Lifecycle:** Experimental

## Purpose

This detection identifies files or folders being created in browser extension directories by a process that is **not** a browser such as Chrome, Edge, Brave, or Firefox.

This matters because malicious software may install or stage a browser extension outside the normal browser workflow in order to:

- Establish persistence
- Inject content into browser sessions
- Steal credentials or cookies
- Monitor browsing activity
- Redirect traffic or manipulate web content

## Detection Logic Summary

The rule reviews `DeviceFileEvents` for file activity in common Chrome, Edge, and Brave extension directories. It looks for:

- `manifest.json` creation
- Extension folder paths matching a 32-character extension ID pattern
- Initiating processes that are **not** `chrome.exe`, `msedge.exe`, `brave.exe`, or `firefox.exe`

## Likely Analyst Goal

Determine whether the extension files were:

- Created by a legitimate enterprise deployment or profile restore process
- Part of authorized developer testing
- Staged by a suspicious script, archive extractor, installer, or malware process

## Initial Triage Questions

1. Which browser profile path was modified?
2. What extension ID or extension folder was written?
3. What process created the files?
4. Was that process expected on the host?
5. Is the extension approved, enterprise-managed, or known-good?
6. Are there nearby signs of credential theft, browser tampering, or persistence?

---

## Investigation Steps

### 1. Validate the File Path

Review the following fields from the alert:

- `FolderPath`
- `FileName`

Focus on whether the write occurred in a real browser extension directory such as:

- Chrome user profile extension folders
- Edge user profile extension folders
- Brave user profile extension folders

Pay close attention to:

- `manifest.json`
- Extension ID folders
- Whether the path is under a real browser profile such as `Default\Extensions\`

**Why this matters:**  
A true extension install or staging event will usually involve a browser extension directory and either a valid extension ID-style folder or a manifest file.

---

### 2. Identify the Extension ID

Extract the extension ID from the folder path if present.

Examples:

- `...\Extensions\<32_char_extension_id>\`
- Nested version folders under that extension ID

Determine whether the extension ID maps to:

- A known approved extension
- An enterprise-managed extension
- A documented business-required extension
- An unknown or suspicious extension

**Why this matters:**  
A known extension ID may explain the alert immediately. An unknown extension ID may indicate unauthorized persistence.

---

### 3. Review the Initiating Process

Inspect:

- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `InitiatingProcessAccountName`

Look for suspicious initiators such as:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- Archive tools
- Installers running from temp folders
- Unsigned utilities
- Processes launched from user-writable locations

Questions to answer:

- Is this process expected in your environment?
- Was it launched by the user, by software deployment tooling, or by another suspicious parent process?
- Did it run from `%TEMP%`, Downloads, AppData, or another unusual path?
- Did the command line reference zip extraction, profile copying, browser policy modification, or extension unpacking?

**Why this matters:**  
The initiating process is often the fastest way to separate legitimate admin or deployment activity from suspicious extension staging.

---

### 4. Determine Whether the Extension Was Enterprise-Managed

Validate whether:

- The extension is part of an approved browser extension baseline
- The host is managed by enterprise software deployment tools
- Browser policies pushed the extension
- The event lines up with software rollout, imaging, migration, or restore activity

Benign indicators include:

- Known software deployment agent as initiator
- Known approved extension ID
- Change window or rollout window
- Matching events across many managed hosts
- Documentation showing the extension is required

**Why this matters:**  
Managed extension deployment can look suspicious at the file-event level if a non-browser process performs the write.

---

### 5. Check for Browser Profile Restore or Migration Activity

Review whether the device or user recently underwent:

- Browser migration
- Profile restore
- Workstation refresh
- Backup restore
- New device provisioning
- User profile copy operations

**Why this matters:**  
Legitimate restore or migration workflows may write extension folders in bulk without browser-originated file events.

---

### 6. Check for Developer or Testing Activity

Ask whether:

- The user is a developer or tester
- They are working with unpacked browser extensions
- This is a development workstation
- There is a known internal extension project

**Why this matters:**  
Authorized developer testing may result in manual copying of extension files into profile paths.

---

### 7. Inspect the Manifest and Related Files

If available, inspect the extension contents.

Priority file:

- `manifest.json`

Review for:

- Extension name
- Version
- Permissions requested
- Background scripts
- Content scripts
- Update URLs
- Host permissions
- References to credential access or browser manipulation

Higher-risk signs include:

- Broad website access
- Background persistence behavior
- Obfuscated JavaScript
- References to credential harvesting
- Suspicious external communications
- Mismatch between extension name and behavior

**Why this matters:**  
The manifest often reveals whether the extension is normal, overly privileged, or clearly malicious.

---

### 8. Hunt for Related Activity on the Same Host

Check for nearby events involving:

- Browser credential store access
- Cookie database access
- Login data file access
- Suspicious outbound network connections
- Scheduled tasks
- Run keys
- New services
- Additional files dropped into AppData or temp paths
- Script execution before the extension file creation

Questions to answer:

- Was this part of a larger intrusion chain?
- Did the same process touch browser data files?
- Did the process establish other persistence mechanisms?

---

### 9. Review User and Device Context

Assess:

- Whether the user is high value or privileged
- Whether the host is used for admin activity
- Whether the device has other recent alerts
- Whether the user reported browser issues, popups, redirects, or credential problems

**Why this matters:**  
Even a medium-severity alert may become high priority if it occurs on a sensitive host or alongside other suspicious behavior.

---

## Suggested Investigation Pivots

### Process Pivots

- Initiating process hash
- Initiating process path
- Parent process
- Full command line
- Signer status
- Prevalence across the environment

### File Pivots

- Extension ID folder
- `manifest.json`
- Other files in the same extension directory
- File hash
- First seen / last seen timing

### User Pivots

- Same account on other endpoints
- Recent software installs
- Recent script execution
- Recent browser issues or credential-related alerts

### Device Pivots

- Other extension writes on same system
- Additional persistence activity
- Network connections near alert time
- Malware or EDR detections on same host

---

## Benign Explanations

Common legitimate scenarios include:

1. Legitimate enterprise software deploying approved extensions
2. Browser migration or profile restore activity
3. Developer testing of unpacked extensions

A benign disposition is stronger when the extension is known, approved, documented, and the initiating process is a trusted deployment or admin tool.

---

## Suspicious Indicators

Escalate concern when you observe:

- Unknown extension ID
- Unsigned or rare initiating process
- Process launched from temp, downloads, or user profile paths
- PowerShell, script host, or archive tool creating extension files
- Manifest requests broad permissions
- Nearby browser credential access
- Unusual outbound traffic after install
- Persistence found elsewhere on the host
- User denies installing or testing the extension
- Extension is not approved and not enterprise-managed

---

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- The extension is approved or enterprise-managed
- The initiating process is trusted and expected
- Timing matches deployment, restore, or testing activity
- No related suspicious behavior is found

### Escalate as Suspicious

Escalate when:

- The extension is unknown or unauthorized
- The initiating process is abnormal or suspicious
- Command-line evidence suggests manual staging or script-based installation
- Related credential theft, persistence, or network anomalies are present

### Escalate as Likely Malicious

Escalate as likely malicious when:

- The extension content is clearly malicious
- The same host shows additional compromise indicators
- The extension appears to support credential theft, session hijacking, or stealth persistence

---

## Response Actions

Depending on findings, consider:

- Containing the affected host if malicious activity is suspected
- Removing the unauthorized extension
- Collecting the full extension files for analysis
- Reviewing browser policies and extension allowlists
- Resetting credentials if browser credential theft is suspected
- Hunting for the same extension ID or process across other endpoints
- Escalating to incident response if persistence or credential theft is confirmed

---

## Example Analyst Notes Template

### Analyst Summary

Alert fired for creation of browser extension files in a user profile extension directory by a non-browser process. Detection aligns to browser extension persistence behavior.

### Key Findings

- **Affected device:**  
- **Affected user:**  
- **Browser path modified:**  
- **Extension ID:**  
- **Initiating process:**  
- **Command line:**  
- **Manifest reviewed:**  
- **Approved or enterprise-managed:**  
- **Related suspicious activity observed:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious

---

## Validation Guidance

A useful validation approach is to install a benign test extension and compare normal browser-created file patterns against non-browser initiated writes.

This helps establish:

- What normal browser-driven extension file creation looks like
- Whether legitimate installs are being excluded correctly
- What abnormal non-browser extension staging looks like in telemetry
