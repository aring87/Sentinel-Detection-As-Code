# Suspicious Azure AD Application Registration

## Goal
Identify creation of Azure AD or Entra ID application registrations that may support malicious resource development or persistence.

## Why This Alert Matters
Application registrations can be abused to create durable cloud footholds, gain app-based access, and prepare for consent abuse or service-principal persistence. While application creation is normal in many cloud environments, suspicious or unexpected registrations can indicate staging for later access or manipulation. This guide is based on a rule that reviews `AuditLogs` for operations such as `Add application`, `Add service principal`, and `Update application`. :contentReference[oaicite:15]{index=15}

## What the Detection Is Looking For
This detection reviews `AuditLogs` for:
- `Add application`
- `Add service principal`
- `Update application`

It surfaces:
- time of change
- operation name
- result
- initiating user principal name
- target resources associated with the application change :contentReference[oaicite:16]{index=16}

## Likely ATT&CK Mapping
- **T1583.006** – Acquire Infrastructure: Web Services
- **T1098** – Account Manipulation

## Initial Triage Questions
1. What application or service principal was created or updated?
2. Who initiated the registration?
3. Is the initiator expected to register applications?
4. Is the application newly operationalized or suspiciously named?
5. What credentials, owners, or permissions were added?
6. Was there follow-on service principal sign-in, consent, or mailbox access?
7. Is the event part of approved cloud engineering or tenant onboarding?

## Key Fields To Review
- `TimeGenerated`
- `OperationName`
- `Result`
- `InitiatedByUPN`
- `TargetResources`

## Investigation Steps

### 1. Review the registration event
- Determine whether the event:
  - added an application
  - added a service principal
  - updated an existing application
- Identify the app name and any associated service principal.

### 2. Validate the initiating actor
- Confirm whether the initiator is:
  - cloud engineering
  - identity admin
  - developer
  - unexpected business user
- Unexpected actors raise suspicion.

### 3. Inspect app characteristics
- Review whether the app:
  - is newly created
  - has unusual or generic naming
  - was assigned broad permissions
  - was granted new owners or credentials
- Pay close attention to high-privilege or mail/file-related access.

### 4. Correlate with related app-abuse behavior
Look for:
- new app secret creation
- service principal sign-ins
- OAuth consent events
- mailbox or Graph access
- risky sign-ins by the creator
- device registration or identity-control changes

### 5. Validate approved business context
- Determine whether the registration aligns with:
  - approved application onboarding
  - engineering or tenant setup
  - dev/test environment work
- If yes, document the app owner and purpose.

## Common Benign Explanations
- Approved application onboarding
- Legitimate cloud engineering or identity administration
- Normal dev/test tenant setup activity :contentReference[oaicite:17]{index=17}

## Escalate When
Escalate if:
- the initiator is not expected to create apps
- the app name, ownership, or permissions are suspicious
- follow-on service principal use or consent abuse is observed
- the app appears designed for mail, file, or broad tenant access
- there is no valid onboarding or engineering explanation

## Suggested Response Actions
- Preserve the audit events and app details
- Review the app registration, owners, and permissions directly
- Validate legitimacy with Entra or cloud application owners
- Disable or investigate unauthorized apps as needed
- Search for related service principal or consent activity
- Review the initiator’s sign-ins and recent cloud actions

## Analyst Notes
This is a foundational cloud resource-development analytic. On its own it may be benign, but it becomes high value when paired with secret creation, sign-in activity, or suspicious permissions.