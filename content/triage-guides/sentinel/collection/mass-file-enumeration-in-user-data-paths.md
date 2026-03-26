# Mass File Access in User Data Paths by Uncommon Process Triage Guide

## Rule Overview

**Title:** Mass File Access in User Data Paths by Uncommon Process  
**Rule ID:** SENT-COLL-0002  
**Severity:** Medium  
**Risk Score:** 58  
**Tactic:** Collection  
**Techniques:** T1005 - Data from Local System, T1039 - Data from Network Shared Drive  
**Platform:** Microsoft Sentinel  
**Data Source:** DeviceFileEvents  
**Lifecycle:** Experimental

## Purpose

This detection identifies high-volume access to files in user data paths by uncommon processes, which may indicate collection or staging activity.

This matters because attackers often enumerate or access many files across user directories before:

- Exfiltration
- Compression
- Cloud upload
- Removable media transfer
- Internal staging

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

The rule summarizes activity over 15-minute windows and alerts when:

- `FileTouches >= 200`
- `Paths >= 3`

## Likely Analyst Goal

Determine whether the file activity was:

- Normal backup, sync, indexing, or administrative behavior
- Approved enterprise software activity
- Suspicious mass file enumeration or collection

## Initial Triage Questions

1. What uncommon process touched the files?
2. Is the process normal for the host or business workflow?
3. How broad was the file access?
4. Was the activity followed by archiving, upload, or transfer?
5. Is there evidence of local or remote data staging?

---

## Investigation Steps

### 1. Review the Process Identity

Inspect:

- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `InitiatingProcessAccountName`

Determine whether the process is:

- Known and approved
- Rare or previously unseen
- Unsigned
- Running from a suspicious path

**Why this matters:**  
Uncommon processes touching large numbers of user files can indicate collection tooling.

---

### 2. Review the Volume and Path Distribution

Assess:

- Number of file touches
- Number of distinct paths
- Whether activity spans multiple user folders
- Whether the activity is broad or narrowly targeted

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

- Parent process
- Signer information
- File path
- Launch location
- User-writable directory execution
- Script host usage

Focus on whether the process launched from:

- `%TEMP%`
- Downloads
- AppData
- USB media
- Network shares

**Why this matters:**  
Execution context often shows whether a process is legitimate software or suspicious tooling.

---

### 5. Hunt for Follow-On Staging or Exfiltration

Look for nearby events involving:

- Archive creation
- ZIP or RAR usage
- Cloud upload
- Email transfer
- USB transfer
- Copies into temp folders
- Outbound network connections

**Why this matters:**  
Mass file access followed by transfer or compression is highly suspicious.

---

### 6. Assess the User and Host

Review:

- Whether the host is a workstation, admin system, or high-value endpoint
- Whether the user works with large file collections
- Whether similar file access has happened before
- Whether other alerts exist on the same system

**Why this matters:**  
Collection behavior on finance, HR, executive, or admin systems can have greater impact.

---

## Benign Explanations

Common legitimate scenarios include:

1. Backup, indexing, sync, or anti-malware scanning
2. Bulk file handling by administrators or approved enterprise tooling
3. Software inventory or migration utilities

---

## Suspicious Indicators

Escalate concern when you observe:

- Rare or unsigned process touching many files
- Execution from temp or user-writable paths
- Mass access followed by compression or transfer
- Similar activity across multiple hosts
- Concurrent credential or browser data access
- Other compromise indicators on the host

---

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- The process is approved and expected
- The volume aligns to backup, inventory, or migration workflows
- No staging or exfiltration is observed

### Escalate as Suspicious

Escalate when:

- The process is uncommon or suspicious
- File access volume is abnormal for the host
- There is evidence of staging or transfer preparation

### Escalate as Likely Malicious

Escalate as likely malicious when:

- Mass file access clearly supports collection behavior
- Exfiltration or staging is confirmed
- The device shows broader intrusion evidence

---

## Response Actions

Depending on findings, consider:

- Isolating the device
- Collecting the binary and execution artifacts
- Hunting for the same process across endpoints
- Reviewing cloud, email, and removable media activity
- Escalating to incident response for suspected collection and staging

---

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
- **Expected business purpose:**  
- **Nearby staging or exfiltration behavior:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious
