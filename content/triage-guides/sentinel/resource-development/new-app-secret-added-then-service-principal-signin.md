# New App Secret Added Then Service Principal Sign-In

## Goal
Identify application secret or key credential creation followed shortly by service principal sign-in, which may indicate suspicious cloud application operationalization.

## Why This Alert Matters
Attackers may register or modify cloud applications, add a secret or key credential, and then immediately use that application identity to access cloud resources. This can create persistence, evade user-focused controls, and allow long-term service-principal-based abuse. This guide is based on a rule that correlates app secret or key-credential creation in `AuditLogs` with follow-on service principal sign-in activity in `SigninLogs` within four hours. :contentReference[oaicite:9]{index=9}

## What the Detection Is Looking For
This detection correlates:
- `Add password credential`
- `Add key credential`

with later service principal sign-ins where:
- the app display name matches
- sign-in occurs shortly after secret creation

It surfaces:
- secret creation time
- sign-in time
- app name
- initiator
- IP address
- target resource
- result code :contentReference[oaicite:10]{index=10}

## Likely ATT&CK Mapping
- **T1528** – Steal Application Access Token
- **T1098** – Account Manipulation

## Initial Triage Questions
1. Which app had a secret or key added?
2. Who added the credential?
3. How soon after the change did the service principal sign in?
4. What resources did the service principal access?
5. Was the secret addition approved and expected?
6. Is the app newly created, overprivileged, or unusual for the tenant?
7. Was there related consent abuse, app registration, or suspicious sign-in activity?

## Key Fields To Review
- `SecretTime`
- `SigninTime`
- `AppName`
- `OperationName`
- `InitiatedBy`
- `IPAddress`
- `ResourceDisplayName`
- `ResultType`

## Investigation Steps

### 1. Review the credential addition
- Determine whether the app received:
  - a password credential
  - a key credential
- Identify who or what initiated the change.
- Confirm whether the app was already known and approved.

### 2. Review the service principal sign-in
- Check how soon the app identity signed in after secret creation.
- Determine whether the sign-in used:
  - a normal corporate source
  - suspicious hosting infrastructure
  - a new or unusual IP range

### 3. Assess app risk
- Review whether the app is:
  - newly created
  - broadly privileged
  - tied to suspicious permissions
  - associated with unusual ownership or consent activity
- Prioritize apps with broad tenant access or mail/file permissions.

### 4. Correlate with related cloud-abuse indicators
Look for:
- suspicious Azure AD / Entra app registration
- OAuth consent abuse
- mailbox access
- SharePoint or OneDrive access
- risky sign-ins by the initiating user
- app-owner changes

### 5. Validate approved onboarding or rotation
- Confirm whether the change aligns with:
  - application onboarding
  - secret rotation
  - automation deployment
  - certificate or credential maintenance
- Legitimate cases should usually be verifiable with app owners.

## Common Benign Explanations
- Approved application onboarding and secret rotation
- Legitimate service principal activation shortly after key rotation :contentReference[oaicite:11]{index=11}

## Escalate When
Escalate if:
- the credential addition was not approved
- the app signs in almost immediately after the secret is added
- the app is unknown, overprivileged, or newly created
- the source IP or resource access is unusual
- there are related consent, mailbox, or SharePoint abuse indicators

## Suggested Response Actions
- Preserve the audit and sign-in evidence
- Validate the app and credential change with cloud owners
- Review app permissions and recent resource access
- Revoke or rotate suspicious credentials if needed
- Search for similar app-secret-plus-sign-in sequences elsewhere
- Investigate the initiating identity for broader compromise

## Analyst Notes
This is one of the stronger cloud resource-development detections because it links setup activity directly to operational use of the new credential.