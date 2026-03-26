# Mass File Enumeration in User Data Paths Triage Guide

## Rule Overview

**Title:** Mass File Access in User Data Paths by Uncommon Process  
**Rule ID:** SENT-COLL-0002  
**Status:** Experimental  
**Severity:** Medium  
**Risk Score:** 58  
**Tactic:** Collection  
**Techniques:** T1005 - Data from Local System, T1039 - Data from Network Shared Drive  
**Platform:** Microsoft Sentinel  
**Data Source:** DeviceFileEvents

## Purpose

This detection identifies high-volume access to files in user data paths by uncommon processes, which may indicate collection or staging activity.

This matters because attackers often enumerate or access large numbers of files before:

- exfiltration
- compression
- cloud upload
- removable media transfer
- internal staging

## Detection Logic Summary

The rule reviews `DeviceFileEvents` in common user data paths such as:

- `\Users\`
- `\Desktop\`
- `\Documents\`
- `\Downloads\`

It excludes common expected processes such as:

- `explorer.exe`
- `SearchIndexer.exe`
- `OneDrive.exe`
- `MsMpEng.exe`
- `svchost.exe`

The rule summarizes activity over a 15-minute window and alerts when:

- `FileTouches >= 200`
- `Paths >= 3`

It also captures sample folder paths for quick triage context.

## Likely Analyst Goal

Determine whether the file activity was:

- normal backup, sync, indexing, or administrative behavior
- approved enterprise software activity
- suspicious mass file enumeration or collection

## Initial Triage Questions

1. What uncommon process touched the files?
2. Is that process normal for the host or business workflow?
3. How broad was the file access?
4. Was the activity followed by archiving, upload, email transfer, or removable media use?
5. Is there evidence of local or remote data staging?

---

## Investigation Steps

### 1. Review the Process Identity

Inspect:

- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `InitiatingProcessAccountName`

Determine whether the process is:

- known and approved
- rare or previously unseen
- unsigned
- running from a suspicious path

**Why this matters:**  
Uncommon processes touching large numbers of user files can indicate collection tooling.

---

### 2. Review the Volume and Path Distribution

Assess:

- number of file touches
- number of distinct paths
- whether the activity spans multiple user folders
- whether the activity is broad or narrowly targeted

Review the sample paths returned by the alert and determine whether they align to:

- normal user work
- bulk processing
- broad document harvesting

**Why this matters:**  
Broad access across many directories is more consistent with automated enumeration or staging.

---

### 3. Determine Whether the Activity Is Expected

Ask:

- Is this a backup, sync, or migration utility?
- Is the device undergoing software inventory or migration?
- Does the process belong to approved enterprise tooling?
- Does the user role justify large-scale file interaction?

**Why this matters:**  
Some enterprise tools touch large file volumes as part of normal operations.

---

### 4. Review the Execution Context

Check:

- parent process
- signer information
- file path
- launch location
- user-writable directory execution
- script host usage

Focus on whether the process launched from:

- `%TEMP%`
- Downloads
- AppData
- USB media
- network shares

**Why this matters:**  
Execution context often shows whether a process is legitimate software or suspicious tooling.

---

### 5. Hunt for Follow-On Staging or Exfiltration

Look for nearby events involving:

- archive creation
- ZIP or RAR usage
- cloud upload
- email transfer
- USB transfer
- copies into temp folders
- outbound network connections

**Why this matters:**  
Mass file access followed by transfer or compression is highly suspicious.

---

### 6. Assess the User and Host

Review:

- whether the host is a workstation, admin system, or high-value endpoint
- whether the user normally works with large file collections
- whether similar file access has happened before
- whether other alerts exist on the same system

**Why this matters:**  
Collection behavior on finance, HR, executive, or admin systems can have greater impact.

---

## Benign Explanations

Common legitimate scenarios include:

1. Backup, indexing, sync, or anti-malware scanning
2. Bulk file handling by administrators or approved enterprise tooling
3. Software inventory or migration utilities

## Suspicious Indicators

Escalate concern when you observe:

- rare or unsigned process touching many files
- execution from temp or user-writable paths
- mass access followed by compression or transfer
- similar activity across multiple hosts
- concurrent credential or browser data access
- other compromise indicators on the host

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- the process is approved and expected
- the volume aligns to backup, inventory, or migration workflows
- no staging or exfiltration is observed

### Escalate as Suspicious

Escalate when:

- the process is uncommon or suspicious
- file access volume is abnormal for the host
- there is evidence of staging or transfer preparation

### Escalate as Likely Malicious

Escalate as likely malicious when:

- mass file access clearly supports collection behavior
- exfiltration or staging is confirmed
- the device shows broader intrusion evidence

## Response Actions

Depending on findings, consider:

- isolating the device
- collecting the binary and execution artifacts
- hunting for the same process across endpoints
- reviewing cloud, email, and removable media activity
- escalating to incident response for suspected collection and staging

## Example Analyst Notes Template

### Analyst Summary

Alert fired for mass file access in user data paths by an uncommon process, potentially indicating data collection or staging activity.

### Key Findings

- **Affected device:**  
- **Affected user:**  
- **Process:**  
- **Command line:**  
- **File touch volume:**  
- **Distinct paths:**  
- **Sample paths:**  
- **Expected business purpose:**  
- **Nearby staging or exfiltration behavior:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious

## Validation Guidance

Use a benign script to recurse through user folders in a lab and tune thresholds against normal platform noise so expected enterprise activity does not trigger excessive alerts.
