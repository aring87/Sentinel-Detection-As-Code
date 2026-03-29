# SharePoint or SaaS Third-Party Integration Secret Access

## Goal
Identify suspicious access or modification activity involving third-party integration credentials or application secrets in cloud and SaaS environments.

## Why This Alert Matters
Integration secrets, app credentials, config files, and token-bearing documents are high-value targets for attackers because they can unlock downstream SaaS, cloud, or supply-chain access. Access to SharePoint or cloud-hosted files containing secrets, combined with app or credential changes, may indicate preparation for broader compromise or persistence. This guide is based on a rule that combines `AuditLogs` application-change activity with `OfficeActivity` access to SharePoint paths containing words like `secret`, `credential`, `integration`, `appsettings`, `config`, or `token`. :contentReference[oaicite:12]{index=12}

## What the Detection Is Looking For
This detection reviews:
- `AuditLogs` for:
  - `Update application`
  - `Add service principal`
  - `Add password credential`
  - `Add key credential`
- `OfficeActivity` for:
  - `FileAccessed`
  - `FileDownloaded`
  - `FileModified`

where SharePoint or document paths contain likely secret-related terms such as:
- `secret`
- `credential`
- `integration`
- `appsettings`
- `config`
- `token` :contentReference[oaicite:13]{index=13}

## Likely ATT&CK Mapping
- **T1552** – Unsecured Credentials
- **T1580** – Cloud Infrastructure Discovery

## Initial Triage Questions
1. What file, config object, or application was accessed or changed?
2. Did the actor maintain integrations as part of their normal role?
3. Was the activity in SharePoint, AuditLogs, or both?
4. Were third-party integration secrets, config files, or token-bearing docs involved?
5. Did the same actor later use related APIs, apps, or service principals?
6. Was there overlap with suspicious app registration or consent activity?
7. Does the activity point to supply-chain or cloud-credential targeting?

## Key Fields To Review
- `TimeGenerated`
- `SourceTable`
- `OperationName`
- `InitiatedBy`
- `TargetResources`
- `Result`
- `UserId`
- `Operation`
- `OfficeObjectId`
- `SourceRelativeUrl`

## Investigation Steps

### 1. Identify the secret-bearing asset
- Determine whether the event involved:
  - app credentials
  - service principal credentials
  - configuration files
  - token files
  - integration secrets in SharePoint or SaaS repositories
- Review the file path or application object involved.

### 2. Review the actor
- Confirm whether the actor normally:
  - maintains integrations
  - administers apps
  - manages SharePoint configuration repositories
- Unexpected access by a normal business user is more suspicious.

### 3. Correlate with downstream usage
Look for:
- API activity
- cloud sign-ins
- consent changes
- new app secrets
- service principal sign-ins
- file export or download bursts

### 4. Assess supply-chain or cloud-risk angle
- Determine whether the integration connects to:
  - GitHub
  - AWS
  - Azure
  - third-party SaaS
  - internal automation platforms
- Secrets tied to external or high-privilege integrations are higher priority.

### 5. Validate legitimate maintenance context
- Confirm whether the action aligns with:
  - approved secret rotation
  - SharePoint admin work
  - developer maintenance
  - integration updates
- If so, record the context for tuning.

## Common Benign Explanations
- Approved integration maintenance
- Legitimate application secret rotation
- Normal SharePoint admin or developer configuration work :contentReference[oaicite:14]{index=14}

## Escalate When
Escalate if:
- the actor is not expected to maintain integrations
- sensitive token or config files were downloaded or modified
- there are related app-registration, app-secret, or consent events
- downstream API or service-principal use follows the access
- the target integration is high value or externally exposed

## Suggested Response Actions
- Preserve the file-access and audit records
- Review the affected integration files or app objects
- Validate the changes with app or SharePoint owners
- Rotate exposed secrets if compromise is suspected
- Search for linked API or service-principal activity
- Review related app registration and cloud identity telemetry

## Analyst Notes
This is a strong hybrid resource-development and credential-access analytic. It becomes especially important when SharePoint config access is followed by cloud application changes or API use.