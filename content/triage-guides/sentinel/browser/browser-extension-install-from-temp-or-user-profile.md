# Browser Extension Install from Temp or User Profile Triage Guide

## Rule Overview

**Title:** Browser Extension Files Created by Non-Browser Process  
**Rule ID:** SENT-BROW-0001  
**Severity:** Medium  
**Risk Score:** 60  
**Status:** Experimental  
**Tactic:** Persistence  
**Technique:** T1176 - Browser Extensions  
**Platform:** Microsoft Sentinel  
**Data Source:** DeviceFileEvents

## Purpose

This detection identifies creation of browser extension files or folders inside browser profile extension directories by a process that is **not** the browser itself.

This matters because attackers may attempt to install or stage malicious browser extensions to:

- Establish persistence
- Steal browser credentials or session data
- Monitor browsing activity
- Inject malicious content into web sessions
- Redirect users or tamper with browser behavior

## Detection Logic Summary

The rule reviews `DeviceFileEvents` for activity in browser extension directories associated with:

- Google Chrome
- Microsoft Edge
- Brave

It looks for:

- Creation or access involving `manifest.json`
- Folder paths matching a browser extension ID pattern
- Activity performed by a non-browser process

The rule excludes normal browser executables such as:

- `chrome.exe`
- `msedge.exe`
- `brave.exe`
- `firefox.exe`

## Likely Analyst Goal

Determine whether the extension files were created by:

- Legitimate enterprise extension deployment
- Browser migration or profile restore activity
- Authorized developer testing
- Suspicious installer, script, archive extraction, or malware behavior

## Initial Triage Questions

1. What exact browser extension path was modified?
2. Was `manifest.json` involved?
3. What process created the extension files?
4. Is the extension known and approved?
5. Was the activity part of software deployment, migration, or testing?
6. Are there signs of related credential theft, persistence, or outbound traffic?

---

## Investigation Steps

### 1. Review the Browser Extension Path

Inspect:

- `FolderPath`
- `FileName`

Validate whether the file activity occurred in a legitimate browser extension directory under:

- Chrome user data
- Edge user data
- Brave user data

Pay close attention to:

- `manifest.json`
- Folder names that look like browser extension IDs
- Writes under `Default\Extensions\` or other profile-specific extension paths

**Why this matters:**  
Malicious extension staging usually places files in the same directories used by legitimate browser extensions.

---

### 2. Identify the Extension ID and Extension Content

Extract the extension ID from the folder path when possible.

Then determine:

- Whether the extension is approved
- Whether the extension is enterprise-managed
- Whether the extension appears to be known business software
- Whether it is unknown, suspicious, or newly observed

If available, inspect:

- `manifest.json`
- Related JavaScript or background scripts
- Extension version folders

**Why this matters:**  
Known, approved extensions may explain the alert immediately. Unknown extensions may indicate unauthorized persistence.

---

### 3. Review the Initiating Process

Inspect:

- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `InitiatingProcessAccountName`

Focus on whether the process looks like:

- An installer
- An archive extraction utility
- A script interpreter
- A suspicious executable
- A process running from a temp or user-writable path

Examples of suspicious initiators include:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- Archive utilities
- Unsigned installers
- Processes running from `%TEMP%`, `Downloads`, or `AppData`

**Why this matters:**  
The initiating process is often the clearest signal for separating benign deployment activity from malicious staging.

---

### 4. Determine Whether the Extension Is Approved or Enterprise-Managed

Validate whether the extension is:

- Part of an approved browser extension baseline
- Deployed by enterprise management tooling
- Documented in software approval records
- Expected for the device or user role

Check whether the timing aligns to:

- Software rollout
- Device imaging
- Browser migration
- User profile restoration
- Change windows

**Why this matters:**  
Legitimate software deployment can create extension files without the browser process being the writer.

---

### 5. Check for Browser Migration, Restore, or Developer Activity

Review whether the activity could be explained by:

- Browser profile restore
- Device migration
- New system provisioning
- Developer testing of unpacked extensions
- Internal extension development

Ask:

- Is this a developer workstation?
- Is there a support ticket or migration effort in progress?
- Is the user known to work with browser extensions?

**Why this matters:**  
Migration and testing can produce file writes that resemble extension staging.

---

### 6. Inspect Related Files and Manifest Contents

If the files are available, inspect the extension content.

Priority review items include:

- `manifest.json`
- Declared permissions
- Background scripts
- Content scripts
- Update URLs
- Host permissions

Higher-risk signs include:

- Broad website access
- Obfuscated JavaScript
- Credential-related permissions
- External update infrastructure
- Mismatch between extension name and function

**Why this matters:**  
The manifest often reveals whether the extension is business software, poorly understood, or clearly suspicious.

---

### 7. Hunt for Related Suspicious Activity

Check for nearby activity involving:

- Browser credential store access
- Cookie or session database access
- Suspicious outbound network traffic
- New persistence mechanisms
- Script execution
- Additional files written to AppData or temp locations

Focus on whether the same process also:

- Accessed browser data
- Downloaded files
- Established persistence
- Contacted rare external destinations

**Why this matters:**  
Malicious browser extension installation often happens alongside other credential theft or persistence activity.

---

### 8. Assess User and Host Context

Review:

- Whether the user is privileged or high value
- Whether the host is sensitive
- Whether there are related alerts on the device
- Whether the user reported browser changes, popups, redirects, or login issues

**Why this matters:**  
A medium-severity alert can become high priority when it affects a high-value user or compromised host.

---

## Benign Explanations

Common legitimate scenarios include:

1. Legitimate enterprise software deploying approved extensions
2. Browser migration or profile restore activity
3. Developer testing of unpacked extensions

## Suspicious Indicators

Escalate concern when you observe:

- Unknown extension IDs
- Non-browser processes writing `manifest.json`
- Script or installer activity from temp or user profile paths
- No approved enterprise reason for the extension
- Broad or suspicious permissions in the manifest
- Nearby browser credential theft behavior
- Suspicious outbound traffic or other persistence activity

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- The extension is approved or enterprise-managed
- The initiating process is trusted and expected
- The timing matches deployment, restore, or testing activity
- No related suspicious behavior is found

### Escalate as Suspicious

Escalate when:

- The extension is unknown or unauthorized
- The initiating process is suspicious or poorly understood
- The activity does not align to expected admin or user workflows
- Related suspicious behavior is present nearby

### Escalate as Likely Malicious

Escalate as likely malicious when:

- The extension content appears malicious
- The same process shows browser credential theft or persistence behavior
- The host shows multiple indicators of compromise
- The extension appears to support unauthorized monitoring, theft, or session tampering

## Response Actions

Depending on findings, consider:

- Isolating the affected device
- Collecting the extension files for analysis
- Removing the unauthorized extension
- Blocking or containing the initiating process
- Reviewing browser extension policies and allowlists
- Resetting credentials if browser theft is suspected
- Escalating to incident response if persistence or compromise is confirmed

## Example Analyst Notes Template

### Analyst Summary

Alert fired for browser extension file creation in a browser profile directory by a non-browser process, potentially indicating unauthorized extension staging or installation.

### Key Findings

- **Affected device:**  
- **Affected user:**  
- **Browser path modified:**  
- **Extension ID:**  
- **Manifest present:**  
- **Initiating process:**  
- **Command line:**  
- **Approved or enterprise-managed:**  
- **Related suspicious activity:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious

## Validation Guidance

A useful validation method is to install a benign test extension and compare:

- Normal browser-created extension file patterns
- Non-browser initiated extension file writes

This helps establish a baseline for expected browser extension installation behavior and makes abnormal staging easier to identify.
