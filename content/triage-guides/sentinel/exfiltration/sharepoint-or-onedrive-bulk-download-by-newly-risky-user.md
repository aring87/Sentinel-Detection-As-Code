# SharePoint or OneDrive Bulk Download by Newly Risky User

## Goal
Identify high-volume SharePoint or OneDrive download activity by a user who recently had a risky or unusual sign-in.

## Why This Alert Matters
Attackers who gain access to cloud identities often move quickly to collect data from SharePoint and OneDrive. When a user with a recent risky or device-code-related sign-in begins performing high-volume downloads, the activity may reflect post-compromise collection and preparation for exfiltration. This guide is based on a rule that correlates risky sign-ins from `SigninLogs` with bulk SharePoint or OneDrive downloads from `OfficeActivity`. :contentReference[oaicite:33]{index=33}

## What the Detection Is Looking For
This detection correlates:
- recent risky or unusual successful sign-ins
- bulk file download activity from:
  - OneDrive
  - SharePoint

It pays special attention to users with:
- medium or high risk
- non-dismissed risk states
- device-code authentication

It then looks for large download volumes within a follow-on time window. :contentReference[oaicite:34]{index=34}

## Likely ATT&CK Mapping
- **T1213** – Data from Information Repositories
- **T1567** – Exfiltration Over Web Service

## Initial Triage Questions
1. What risky or unusual sign-in preceded the download activity?
2. How many files were downloaded and from which workload?
3. Which sites, libraries, or objects were involved?
4. Is the user’s download volume normal?
5. Did the activity target high-value SharePoint sites or sensitive OneDrive content?
6. Are there related mailbox, OAuth, or app-consent indicators?
7. Was the sign-in associated with phishing, device code abuse, or token misuse?

## Key Fields To Review
- `LastRiskySignin`
- `FirstSeen`
- `LastSeen`
- `UserUpn`
- `OfficeWorkload`
- `DownloadCount`
- `Sites`
- `Objects`

## Investigation Steps

### 1. Review the risky sign-in
- Determine why the sign-in was risky:
  - medium/high risk level
  - unresolved risk state
  - device code sign-in
  - unusual geography or IP
- Confirm whether the user expected the access path.

### 2. Review the bulk downloads
- Identify whether the activity affected:
  - OneDrive
  - SharePoint
  - both
- Review volume, time window, and targeted sites or objects.
- Determine whether the content likely includes sensitive business data.

### 3. Assess repository sensitivity
- Prioritize:
  - executive or finance sites
  - HR or legal content
  - engineering or source-code repositories
  - regulated or confidential document libraries
- Bulk download from sensitive repositories is especially concerning.

### 4. Correlate with other cloud abuse
Look for:
- inbox rule creation
- Graph mail access
- app registration
- consent abuse
- suspicious external sharing
- cloud storage uploads
- unusual endpoint execution after the sign-in

### 5. Validate legitimate use
- Determine whether the user was:
  - performing a planned export
  - doing sync or migration
  - running approved backup or investigation tasks
- If not, escalate.

## Common Benign Explanations
- Approved migration or sync events after legitimate risk changes
- Planned content export by authorized users
- Large but expected business downloads :contentReference[oaicite:35]{index=35}

## Escalate When
Escalate if:
- the risky sign-in context is suspicious or unresolved
- the download volume is abnormal for the user
- sensitive SharePoint or OneDrive content is involved
- the user also shows mailbox, OAuth, or forwarding-rule abuse
- the activity appears immediately after phishing or device-code indicators

## Suggested Response Actions
- Preserve sign-in and OfficeActivity telemetry
- Review file and site sensitivity with SharePoint or M365 admins
- Revoke sessions or force reauthentication if compromise is suspected
- Search for similar behavior across other risky users
- Contain the account and review related cloud abuse indicators
- Investigate whether data was subsequently uploaded, shared, or transferred out

## Analyst Notes
This is a strong cloud-sequence analytic because it ties identity risk directly to high-volume data collection. It is especially valuable for catching post-phish cloud-only intrusions before or during exfiltration.