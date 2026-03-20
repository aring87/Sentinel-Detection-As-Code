# OneDrive File Exfiltration

## Goal
Identify suspicious file upload activity to OneDrive that may represent data exfiltration.

## Why This Alert Matters
Cloud storage is a common exfiltration path because it blends into normal user activity. OneDrive uploads can be legitimate collaboration, but they can also be used to move data to unauthorized or personal storage locations.

## What the Detection Is Looking For
This detection looks for `CloudAppEvents` where:
- `Application == "OneDrive"`
- upload-related activity indicates files were sent to the cloud

## Likely ATT&CK Mapping
- T1567.002 – Exfiltration to Cloud Storage

## Initial Triage Questions
1. Which user performed the upload?
2. Was the OneDrive destination expected and organizationally managed?
3. Was the upload volume normal for that user?
4. Were the uploaded files sensitive, bulk, or recently staged?
5. Was there related collection or archive activity beforehand?

## Key Fields To Review
- user/account identifier
- application
- action type
- object or file name
- timestamp
- tenant or destination context if available

## Investigation Steps
### 1. Validate the upload event
- Confirm the action type reflects upload behavior.
- Determine whether the upload was interactive, synced, or application-driven.

### 2. Identify the account and destination context
- Confirm whether the upload went to:
  - corporate OneDrive
  - another tenant
  - a personal or unmanaged cloud destination
- Determine whether cross-tenant or abnormal sharing behavior exists.

### 3. Assess upload content
- Review object names if available.
- Identify whether files appear sensitive, bulk, or archive-based.
- Check for recent ZIP, RAR, or 7Z creation on the endpoint.

### 4. Correlate with endpoint activity
Look for:
- archive creation
- mass file access
- PowerShell or script-based collection
- email exfiltration attempts
- unusual network or browser upload behavior

### 5. Compare to baseline
- Does this user normally upload files to OneDrive?
- Is the time of day, device, or volume unusual?
- Is the uploading device unmanaged, high-risk, or newly enrolled?

## Common Benign Explanations
- normal user collaboration
- standard OneDrive sync activity
- project migrations
- bulk upload during business workflow

## Escalate When
Escalate if:
- destination appears personal or unapproved
- file volume or sensitivity is abnormal
- upload follows collection or archive creation
- user context does not match normal behavior
- related alerts exist on the same user or endpoint

## Suggested Response Actions
- review cloud audit details and object names
- check sharing, tenant, and session context
- preserve related endpoint telemetry
- restrict account or session if active data theft is suspected
- involve IR and data owners for data impact assessment

## Analyst Notes
This guide is intentionally broad and useful for general OneDrive upload review. It complements, rather than fully replaces, the bulk-upload spike guide.