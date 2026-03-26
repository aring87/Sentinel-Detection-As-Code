# Triage Guide: Data Collection from Local System

## Detection Title
Data Collection from Local System

## Detection ID
dodea-sig-018-data-collection-from-local-system

## Objective

This detection identifies access to user data locations and common document types on the local system. It is intended to surface behavior that may indicate collection of sensitive files for staging, review, or later exfiltration.

## Why It Matters

Attackers commonly collect data from local systems before exfiltration. Targeted file types such as:
- `.docx`
- `.pdf`
- `.xls`
- `.csv`

may indicate interest in business documents, reports, exports, or user-generated content.

This detection is most meaningful when tied to suspicious process context or follow-on staging behavior.

## Alert Logic Summary

The rule looks for file activity in paths such as:
- `C:\Users\`
- `Desktop`
- `Documents`

and file types such as:
- `.docx`
- `.pdf`
- `.xls`
- `.csv`

## Initial Triage Questions

- Which process accessed the files?
- Which user context was involved?
- Was the file access normal for the user’s role?
- Was this isolated file access or part of a broader pattern?
- Were files later compressed, copied, or transferred?

## Investigation Steps

1. Review the affected device and user context.
2. Review the file names, folders, and action types involved.
3. Identify the initiating process if available in related telemetry.
4. Determine whether the file access pattern aligns with:
   - user productivity
   - backup/indexing
   - document search
   - suspicious staging behavior
5. Check for related behavior:
   - archive creation
   - cloud upload
   - outbound network transfer
   - removable media access
6. Review whether the same process touched many files or multiple folders.

## Common False Positives

- legitimate user access to personal or work documents
- indexing and search services
- backup tools
- anti-malware scanning
- DLP or compliance tooling
- file preview behavior in normal workflows

## Escalation Guidance

Escalate when:
- a suspicious process accesses many document files
- file access is followed by compression or outbound transfer
- the user or host context is unusual
- access occurs during off-hours or from suspicious sessions
- the file access pattern is inconsistent with the user’s role

## Recommended Enrichment

- file access timeline
- associated process telemetry
- archive creation telemetry
- outbound network activity
- removable media usage
- cloud application events
- user role and host criticality

## ATT&CK Mapping

- Collection
- T1005 – Data from Local System

## Related Rule

- `detections/sentinel/collection/data-collection-from-local-system.yml`
