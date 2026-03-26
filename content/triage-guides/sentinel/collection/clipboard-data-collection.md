# Clipboard Data Collection Triage Guide

## Rule Overview

**Title:** Suspicious Clipboard Read or Clipboard Utility Execution  
**Rule ID:** SENT-COLL-0001  
**Status:** Experimental  
**Severity:** Medium  
**Risk Score:** 55  
**Tactic:** Collection  
**Technique:** T1115 - Clipboard Data  
**Platform:** Microsoft Sentinel  
**Data Source:** DeviceProcessEvents

## Purpose

This detection identifies suspicious clipboard read activity or clipboard utility execution that may indicate collection of copied data, secrets, or credentials.

This matters because attackers may read clipboard contents to capture:

- Passwords copied by users
- MFA codes
- Sensitive text copied from terminals, documents, or chat tools
- Secrets copied during administration or troubleshooting
- Data staged for later exfiltration

## Detection Logic Summary

The rule reviews `DeviceProcessEvents` for clipboard-related execution involving:

- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `clip.exe`

It looks for command lines containing clipboard read patterns such as:

- `Get-Clipboard`
- `[Windows.Forms.Clipboard]::GetText`
- `GetText()`
- `clip.exe`

The rule excludes:

- `Set-Clipboard`
- likely development-focused parent processes such as:
  - `Code.exe`
  - `devenv.exe`
  - `powershell_ise.exe`

## Likely Analyst Goal

Determine whether the clipboard access was:

- Legitimate administrator or developer scripting
- Expected automation or troubleshooting
- Suspicious collection of copied secrets or credentials

## Initial Triage Questions

1. Which process read the clipboard?
2. Is clipboard access normal for this user or host?
3. What launched the clipboard-related process?
4. Did clipboard access occur near archive creation, browser credential access, or outbound transfers?
5. Was the process launched from a suspicious path or process tree?

---

## Investigation Steps

### 1. Review the Clipboard-Related Process

Inspect:

- `FileName`
- `ProcessCommandLine`
- `AccountName`

Pay close attention to commands such as:

- `Get-Clipboard`
- `[Windows.Forms.Clipboard]::GetText`
- `GetText()`

**Why this matters:**  
Command-line clipboard reads are less common than normal interactive clipboard use and may indicate scripting or collection behavior.

---

### 2. Review the Initiating Process and Process Tree

Inspect:

- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`

Determine whether the clipboard access was launched by:

- PowerShell
- command shell
- a script runner
- a management tool
- a suspicious parent process

Pay attention to:

- execution from `%TEMP%`
- `Downloads`
- `AppData`
- LOLBins
- unusual parent-child relationships

**Why this matters:**  
The surrounding process tree often distinguishes benign scripting from attacker tradecraft.

---

### 3. Determine Whether the Activity Is Expected

Ask:

- Does the account normally use PowerShell or command-line clipboard access?
- Is this an admin, developer, or automation-heavy workstation?
- Is there a known script or workflow that reads clipboard contents?
- Does the timing align to troubleshooting or approved automation?

**Why this matters:**  
Some clipboard access is normal in technical workflows, but it should still be explainable.

---

### 4. Check for Nearby Collection or Exfiltration Activity

Review the same time window for:

- archive creation
- browser credential access
- email attachment creation
- cloud uploads
- outbound transfers
- additional scripting activity

**Why this matters:**  
Clipboard collection becomes far more concerning when paired with staging or exfiltration behavior.

---

### 5. Assess User and Device Context

Review:

- whether the host is privileged or high value
- whether the user recently reported suspicious behavior
- whether the host has additional collection alerts
- whether the system is an admin workstation, jump box, or developer endpoint

**Why this matters:**  
Clipboard collection on sensitive systems or users raises the priority of the investigation.

---

## Benign Explanations

Common legitimate scenarios include:

1. Legitimate administrator or developer clipboard scripting
2. Automation workflows that intentionally read clipboard contents
3. User troubleshooting or local productivity scripts

## Suspicious Indicators

Escalate concern when you observe:

- clipboard reads by uncommon or unsigned tooling
- execution from temp or user-writable paths
- clipboard access followed by archive creation or transfer
- nearby browser credential access
- suspicious script hosts or LOLBins
- other collection activity on the same host

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- the user regularly uses scripting or automation
- the initiating process is trusted and expected
- the activity aligns to known troubleshooting or admin workflows
- no nearby collection or exfiltration activity is present

### Escalate as Suspicious

Escalate when:

- clipboard access is unusual for the user or host
- the process tree is suspicious or poorly explained
- clipboard access occurs near staging or outbound transfer behavior

### Escalate as Likely Malicious

Escalate as likely malicious when:

- clipboard reads are part of a broader compromise chain
- copied secrets or credentials may have been harvested
- the host shows additional collection, credential theft, or exfiltration activity

## Response Actions

Depending on findings, consider:

- isolating the host if malicious collection is suspected
- reviewing the full process tree and any associated scripts
- hunting for the same command line across the environment
- resetting credentials if copied secrets may have been exposed
- escalating to incident response if broader collection is confirmed

## Example Analyst Notes Template

### Analyst Summary

Alert fired for suspicious clipboard read or clipboard utility execution, potentially indicating collection of copied secrets, credentials, or other sensitive user data.

### Key Findings

- **Affected device:**  
- **Affected user:**  
- **Process:**  
- **Command line:**  
- **Initiating process:**  
- **Expected activity:**  
- **Nearby staging or transfer behavior:**  
- **Related alerts:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious

## Validation Guidance

A useful validation method is to run `Get-Clipboard` in a controlled lab and compare that activity against normal administrator behavior to tune for environment-specific usage.