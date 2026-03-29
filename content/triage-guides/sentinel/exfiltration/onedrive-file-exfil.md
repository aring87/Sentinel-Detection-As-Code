# OneDrive File Upload Activity

## Goal
Identify OneDrive file uploads that may support exfiltration when correlated with risky sign-ins, archive creation, or unusual endpoint behavior.

## Why This Alert Matters
OneDrive is a legitimate and commonly used collaboration platform, which makes it attractive for attacker exfiltration. A single upload is not inherently malicious, but OneDrive file uploads become more suspicious when tied to risky sign-ins, unusual device activity, archive creation, or users who do not normally move data this way. This guide is based on a rule that watches for OneDrive `FileUploaded` activity in `CloudAppEvents`. :contentReference[oaicite:21]{index=21}

## What the Detection Is Looking For
This detection reviews `CloudAppEvents` where:
- `Application == "OneDrive"`
- `ActionType` contains `FileUploaded`

The detection projects the user, application, object name, IP address, and raw event data for review. :contentReference[oaicite:22]{index=22}

## Likely ATT&CK Mapping
- **T1567.002** – Exfiltration to Cloud Storage

## Initial Triage Questions
1. Which user performed the upload?
2. What file or object was uploaded?
3. Was the source device or sign-in context unusual?
4. Is OneDrive upload behavior normal for this user?
5. Did the upload follow archive creation, bulk file access, or risky sign-ins?
6. Was the destination tenant or context expected?
7. Are there related mailbox, SharePoint, or cloud-app indicators nearby?

## Key Fields To Review
- `Timestamp`
- `AccountObjectId`
- `AccountDisplayName`
- `Application`
- `ActionType`
- `ObjectName`
- `IPAddress`
- `RawEventData`

## Investigation Steps

### 1. Review the uploaded object
- Identify the file or object name.
- Determine whether it appears sensitive, compressed, or related to project or identity data.
- If available, review file size, site path, and upload destination context.

### 2. Validate user behavior
- Determine whether the user commonly uploads to OneDrive.
- Compare the event to the user’s normal collaboration or sync habits.
- Pay close attention to uploads by admins, executives, or service accounts.

### 3. Correlate with risky context
Look for:
- risky sign-ins
- archive creation
- bulk file access
- mass document collection
- device code abuse
- suspicious browser credential access
- endpoint staging activity

### 4. Determine whether the destination is expected
- Review whether the upload stayed within enterprise-controlled OneDrive context or crossed into an unusual tenant or account boundary.
- If raw event details support it, confirm the destination user/site/workspace.

### 5. Validate benign collaboration
- Confirm whether the upload was part of:
  - normal sync
  - project handoff
  - document sharing
  - remote work collaboration
- If yes, document the context for tuning.

## Common Benign Explanations
- Normal user collaboration and synchronization
- Approved business uploads :contentReference[oaicite:23]{index=23}

## Escalate When
Escalate if:
- the upload follows archive creation or bulk collection
- the sign-in context is risky or unusual
- the user does not normally upload through OneDrive
- the uploaded object appears sensitive or suspicious
- the same user shows other exfiltration or cloud-abuse indicators

## Suggested Response Actions
- Preserve the upload event and user context
- Review nearby cloud, sign-in, and endpoint activity
- Identify whether the uploaded data is sensitive
- Search for similar uploads by the same user or host
- Coordinate with M365 admins to review file location and sharing state
- Revoke sessions or investigate the account if broader compromise is suspected

## Analyst Notes
This is a useful lower- to medium-confidence exfiltration indicator on its own. It becomes much stronger when combined with risky sign-ins, archive creation, or unusual endpoint collection activity.