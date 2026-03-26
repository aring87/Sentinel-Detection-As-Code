# Data Collection from Local System Triage Guide

## Rule Overview

**Title:** Suspicious Access to Sensitive Local User Documents  
**Rule ID:** SENT-COLL-0005  
**Status:** Experimental  
**Severity:** Medium  
**Risk Score:** 57  
**Tactic:** Collection  
**Technique:** T1005 - Data from Local System  
**Platform:** Microsoft Sentinel  
**Data Source:** DeviceFileEvents

## Purpose

This detection identifies processes accessing potentially sensitive document types in common user data paths, which may indicate collection or staging from the local system.

This matters because attackers often gather user documents during collection activity in order to obtain:

- business documents
- PDFs
- spreadsheets
- presentations
- exported CSV data
- text files containing sensitive information

## Detection Logic Summary

The rule reviews `DeviceFileEvents` for actions such as:

- `FileCreated`
- `FileModified`
- `FileRead`
- `FileAccessed`

It focuses on common user data paths such as:

- `\Users\`
- `\Desktop\`
- `\Documents\`
- `\Downloads\`

It includes file types such as:

- `.docx`
- `.pdf`
- `.xls`
- `.xlsx`
- `.csv`
- `.pptx`
- `.txt`

It excludes common expected processes such as:

- `explorer.exe`
- `SearchIndexer.exe`
- `OneDrive.exe`
- `MsMpEng.exe`

The rule alerts when a process accesses at least:

- 25 files
- across 3 or more distinct paths
- within a 15-minute window

## Likely Analyst Goal

Determine whether the file access was:

- normal business activity
- backup, indexing, sync, or anti-malware behavior
- approved enterprise tooling
- suspicious local document collection or staging

## Initial Triage Questions

1. What process accessed the files?
2. Which account was involved?
3. Is this level of bulk document access normal for the host or user?
4. Are the accessed files sensitive for that role or system?
5. Did archive creation, upload, email transfer, or removable media usage follow?

---

## Investigation Steps

### 1. Identify the Process and Account

Inspect:

- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `InitiatingProcessAccountName`

Determine whether the process is:

- known and approved
- rare in the environment
- running from a suspicious path
- associated with scripts, portable tooling, or temporary execution

**Why this matters:**  
The initiating process is one of the strongest signals for separating legitimate bulk access from suspicious collection.

---

### 2. Review the Scope of File Access

Assess:

- number of files accessed
- number of folders involved
- document types involved
- whether the activity is concentrated in user data paths

Determine whether the activity looks like:

- normal user work
- broad document harvesting
- automated collection or staging

**Why this matters:**  
Access across multiple user folders and many files is consistent with collection workflows.

---

### 3. Determine Whether the Activity Is Expected

Ask:

- Is the process a backup, sync, indexing, or anti-malware tool?
- Is the user performing migration, archival, or bulk document review?
- Is the activity tied to approved enterprise software?
- Does the user role normally involve large-scale file access?

**Why this matters:**  
Legitimate tools and workflows can generate noisy file access patterns.

---

### 4. Check for Follow-On Staging or Exfiltration

Review the same time window for:

- archive creation
- cloud upload
- email attachment activity
- removable media use
- network transfer
- file compression
- copies into temp or staging folders

**Why this matters:**  
Bulk document access followed by staging or transfer is much more suspicious than file access alone.

---

### 5. Review the Execution Context

Check:

- parent process
- signer information
- execution path
- whether the binary is known and prevalent
- whether it launched from a user-writable location

Pay extra attention to:

- PowerShell
- rare executables
- temp directory launches
- unsigned tooling

**Why this matters:**  
The execution context helps determine whether the activity is enterprise tooling or suspicious collection.

---

### 6. Assess User and Device Context

Review:

- whether the host is high value
- whether the account is privileged
- whether the device has recent suspicious alerts
- whether similar activity is normal on that system

**Why this matters:**  
Collection activity on finance, HR, executive, or admin systems may require faster escalation.

---

## Benign Explanations

Common legitimate scenarios include:

1. Backup, indexing, sync, or anti-malware activity
2. Bulk document processing by IT or approved business tooling
3. User-driven search, migration, or archival workflows

## Suspicious Indicators

Escalate concern when you observe:

- unknown or rare process touching many documents
- execution from temp or user profile paths
- sensitive file types across multiple directories
- file access followed by compression, upload, or transfer
- similar behavior on other hosts tied to the same account
- additional collection or exfiltration alerts nearby

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- the process is an approved business or enterprise tool
- the host or account commonly performs bulk file operations
- no staging or exfiltration activity is observed

### Escalate as Suspicious

Escalate when:

- the process is uncommon or poorly understood
- the file access volume is unusual for the user or host
- nearby staging or transfer activity is present

### Escalate as Likely Malicious

Escalate as likely malicious when:

- bulk document access is tied to suspicious tooling
- archive, transfer, or exfiltration clearly follows
- the host shows broader compromise evidence

## Response Actions

Depending on findings, consider:

- isolating the host if large-scale collection is suspected
- collecting the process binary and hash
- hunting for the same process across the environment
- reviewing cloud, email, and removable media activity
- escalating to incident response if staging or exfiltration is confirmed

## Example Analyst Notes Template

### Analyst Summary

Alert fired for suspicious access to sensitive local user documents, potentially indicating collection or staging from the local system.

### Key Findings

- **Affected device:**  
- **Affected user:**  
- **Process:**  
- **Command line:**  
- **Files accessed:**  
- **Folders involved:**  
- **Expected business purpose:**  
- **Nearby archive or upload activity:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious

## Validation Guidance

A useful validation method is to use a benign lab script to access many files across user folders and then tune thresholds against normal environment behavior.
