# Suspicious Azure AD Application Registration

## Goal
Identify creation or modification of Azure AD / Entra ID applications and service principals that may support attacker-controlled infrastructure, persistence, or follow-on cloud abuse.

## Why This Alert Matters
Attackers can register cloud applications and service principals to establish footholds, request permissions, stage phishing infrastructure, or maintain access through OAuth and app-based workflows. New or modified app registrations are not automatically malicious, but they are high-value events that deserve validation, especially when created by users who do not normally perform identity administration. :contentReference[oaicite:4]{index=4}

## What the Detection Is Looking For
This detection reviews `AuditLogs` for operations such as:
- `Add application`
- `Add service principal`
- `Update application`

It also extracts the initiating user and projects the target resources for triage. :contentReference[oaicite:5]{index=5}

## Likely ATT&CK Mapping
- T1583.006 – Acquire Infrastructure: Web Services
- Also relevant to Persistence when abused through app/service-principal access. :contentReference[oaicite:6]{index=6}

## Initial Triage Questions
1. Who initiated the application or service principal change?
2. Is the initiator an authorized cloud or identity administrator?
3. What application name, owner, permissions, and credentials were configured?
4. Was this a legitimate onboarding event, or an unexpected registration?
5. Was there follow-on consent, mailbox access, token use, or suspicious sign-in activity?

## Key Fields To Review
- TimeGenerated
- OperationName
- Result
- InitiatedByUPN
- TargetResources

## Investigation Steps
### 1. Validate the operation
- Confirm whether the event was:
  - `Add application`
  - `Add service principal`
  - `Update application`
- Determine whether the action succeeded.

### 2. Review the application object
- Identify the application name and any associated service principal.
- Review app owners, secrets, certificates, reply URLs, and permissions.
- Determine whether privileged API permissions or broad delegated permissions were requested.

### 3. Review initiator context
- Determine whether the initiating user normally registers applications.
- Check whether the account recently showed risky sign-ins, device-code activity, MFA issues, or suspicious admin behavior.

### 4. Correlate with follow-on cloud abuse
Check for:
- admin or user consent activity
- service principal sign-ins
- mailbox access changes
- suspicious inbox rule creation
- token or OAuth abuse
- unusual external sign-ins

### 5. Assess business context
- Confirm whether the app registration was part of approved development, onboarding, or integration work.
- Check change records or cloud engineering tickets where possible.

## Common Benign Explanations
- Approved application onboarding
- Legitimate cloud engineering work
- Identity administration or integration setup

## Escalate When
Escalate if:
- the initiator is not expected to register applications
- the app requests broad or high-risk permissions
- new secrets/certificates were added unexpectedly
- suspicious consent or service principal activity follows
- the app appears tied to phishing, mailbox access, or persistence

## Suggested Response Actions
- preserve the application name, object details, owners, and credentials
- review and revoke suspicious secrets or certificates if needed
- disable or remove the application/service principal if malicious
- review consent grants and service principal sign-in history
- notify IR and identity/cloud teams

## Analyst Notes
Use this as the canonical app-registration guide. It is stronger than the older legacy rule because it covers application adds, service principal adds, and updates, and it explicitly guides the analyst to review app owners, credentials, permissions, and follow-on consent activity.