# OneDrive or Cloud Storage Bulk Upload Spike

## Goal
Identify unusually high-volume uploads to OneDrive or other cloud storage services that may indicate exfiltration.

## Why This Alert Matters
Bulk cloud uploads can indicate a user or compromised account is moving large quantities of data to sanctioned or semi-sanctioned services. Even when the platform itself is approved, the behavior may still be malicious.

## What the Detection Is Looking For
This detection looks for cloud upload events summarized over a 30-minute period and flags spikes where:
- upload count is high
- distinct file count is high
- activity is associated with cloud storage applications

## Likely ATT&CK Mapping
- T1567.002 – Exfiltration to Cloud Storage

## Initial Triage Questions
1. Which account generated the upload spike?
2. Which cloud application was involved?
3. Was the volume normal for that user or workflow?
4. Were the uploaded files recently collected or archived?
5. Did the uploads go to an expected tenant, workspace, or destination?

## Key Fields To Review
- AccountObjectId
- Application
- Uploads
- FileCount
- Timestamp bucket

## Investigation Steps
### 1. Validate the spike
- Confirm the upload and distinct file counts.
- Compare the activity to the user’s historical baseline.
- Determine whether the spike is isolated or repeated.

### 2. Identify the cloud application and account
- Determine whether activity was in OneDrive or another sanctioned cloud service.
- Confirm whether the account is user-driven, service-based, or shared.

### 3. Review destination trust
- Determine whether the destination tenant, workspace, or repository is expected.
- Check whether the upload targeted a corporate location or an unusual external context.

### 4. Correlate with endpoint staging
Review recent endpoint activity for:
- archive creation
- mass file enumeration
- temp folder staging
- scripting activity
- browser-based upload behavior

### 5. Assess business context
- Was there a migration, backup, or bulk collaboration event?
- Was the user part of an approved project requiring mass uploads?
- Did change records or tickets document the behavior?

## Common Benign Explanations
- legitimate bulk collaboration
- migrations
- backup or sync activity
- onboarding or project-driven file movement

## Escalate When
Escalate if:
- upload volume is unusual for the account
- destination context is unexpected
- archive or collection behavior occurred first
- files appear sensitive or business-critical
- user behavior is inconsistent with role or history

## Suggested Response Actions
- review cloud audit detail for uploaded object names and target context
- investigate related endpoint activity on the user’s device
- temporarily restrict sharing or session access if exfiltration is ongoing
- preserve evidence for IR and data-loss review

## Analyst Notes
This guide is stronger than a simple OneDrive upload detection because it introduces behavior thresholds. It is a good primary guide for cloud exfiltration spikes, while the generic OneDrive guide is still useful for lower-volume suspicious uploads.