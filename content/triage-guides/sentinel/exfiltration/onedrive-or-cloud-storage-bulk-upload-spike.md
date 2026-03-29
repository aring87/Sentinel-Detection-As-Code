# OneDrive or Cloud Storage Bulk Upload Spike

## Goal
Identify spikes in cloud storage upload activity that may indicate large-scale exfiltration to sanctioned or commonly used cloud services.

## Why This Alert Matters
Bulk uploads to cloud services can be legitimate, but they can also signal exfiltration, especially when performed by unusual users or after endpoint collection activity. Unlike a single file upload, a burst of many uploads in a short window may indicate deliberate data transfer rather than routine collaboration. This guide is based on a detection that counts cloud upload activity and distinct files uploaded within a 30-minute window. :contentReference[oaicite:24]{index=24}

## What the Detection Is Looking For
This detection reviews `CloudAppEvents` for upload-related actions such as:
- `FileUploadedToCloud`
- `FileSyncUploadedFull`
- `FileUploaded`

It summarizes:
- total uploads
- distinct uploaded files
- applications involved

The rule triggers when both upload count and file-count thresholds are exceeded in a short period. :contentReference[oaicite:25]{index=25}

## Likely ATT&CK Mapping
- **T1567.002** – Exfiltration to Cloud Storage

## Initial Triage Questions
1. Which user performed the bulk upload?
2. Which cloud application or applications were involved?
3. How many uploads occurred and how many distinct files were involved?
4. Is the volume unusual for the user or team?
5. Was the destination expected and enterprise-controlled?
6. Did the uploads follow archive creation, collection, or risky sign-ins?
7. Was the endpoint or user otherwise suspicious?

## Key Fields To Review
- `AccountObjectId`
- `AccountDisplayName`
- `Timestamp`
- `Uploads`
- `FileCount`
- `Apps`

## Investigation Steps

### 1. Review upload volume and timing
- Confirm how many uploads occurred in the alert window.
- Determine whether the volume is:
  - normal sync behavior
  - migration activity
  - project handoff
  - unusual for the user

### 2. Identify the cloud service
- Review which application or apps were involved.
- Determine whether the service is:
  - OneDrive
  - another enterprise cloud platform
  - sanctioned storage
  - unusual for the user’s role

### 3. Correlate with preceding activity
Look for:
- archive creation
- mass file access
- document collection
- risky sign-ins
- suspicious endpoint process activity
- device code abuse
- consent abuse or mailbox indicators

### 4. Determine data sensitivity
- Review the types of files likely involved.
- If additional telemetry is available, prioritize:
  - archives
  - source code
  - identity data
  - finance or HR content
  - regulated or sensitive documents

### 5. Validate normal business workflows
- Confirm whether the activity aligns with:
  - migration
  - bulk collaboration
  - backup or sync jobs
  - content publishing
- If yes, capture the details for tuning.

## Common Benign Explanations
- Legitimate large-scale sync or migration activity
- Bulk collaboration uploads during business processes
- Approved project handoff or content publishing workflows :contentReference[oaicite:26]{index=26}

## Escalate When
Escalate if:
- upload volume is unusual for the user
- the destination context is unexpected
- the uploads follow archive creation or endpoint collection
- the same user shows risky sign-ins or phishing indicators
- the files likely include sensitive or regulated content

## Suggested Response Actions
- Preserve the upload summary and related cloud telemetry
- Review M365 or cloud logs for destination details
- Investigate the user’s recent endpoint and sign-in activity
- Coordinate with cloud admins to inspect affected files and sharing state
- Search for similar bulk upload behavior across other users
- Contain the account if the upload appears malicious or compromised

## Analyst Notes
This is a strong exfiltration-volume analytic, especially in cloud-first environments. The best discriminator is whether the upload volume and destination are normal for that user and whether collection activity happened beforehand.