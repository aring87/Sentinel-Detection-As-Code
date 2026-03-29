# Suspicious Entra ID Control-Plane Changes by Nonstandard Actor

## Goal
Identify risky Entra ID and hybrid identity control-plane changes that may establish persistence, weaken protections, or expand attacker access.

## Why This Alert Matters
Identity control-plane changes can persist attacker access even when endpoint artifacts are limited or absent. Changes such as updating Conditional Access, adding authentication methods, creating service principal credentials, adding owners to applications, or registering security info may enable long-term access, reduce protections, or prepare for follow-on abuse. This guide is based on a rule that reviews `AuditLogs` for high-risk Entra control-plane operations performed by users or apps. :contentReference[oaicite:11]{index=11}

## What the Detection Is Looking For
This detection reviews `AuditLogs` for actions such as:
- updating conditional access policies
- adding authentication methods
- registering security info
- adding service principal credentials
- updating applications
- adding owners to applications
- adding app role assignments
- adding federated identity credentials

It surfaces:
- actor
- target object
- operation name
- result
- category
- service and details fields :contentReference[oaicite:12]{index=12}

## Likely ATT&CK Mapping
- **T1098** – Account Manipulation
- **T1556** – Modify Authentication Process

## Initial Triage Questions
1. What exact Entra object or policy was changed?
2. Who made the change: user or app?
3. Is the actor expected to perform identity control-plane administration?
4. Did the change weaken protections, add credentials, or create persistence?
5. Was there recent risky sign-in, mailbox abuse, OAuth abuse, or device registration?
6. Is there a valid CAB or change ticket for the action?
7. Did the change affect high-value identities, apps, or authentication controls?

## Key Fields To Review
- `TimeGenerated`
- `OperationName`
- `ActivityDisplayName`
- `Actor`
- `Target`
- `Result`
- `ResultReason`
- `Category`
- `LoggedByService`
- `AdditionalDetails`

## Investigation Steps

### 1. Identify the exact control-plane change
- Determine whether the activity modified:
  - Conditional Access
  - MFA or authentication methods
  - app credentials
  - app ownership
  - federated identity trust
  - security info registration
- Clarify whether the change could enable persistence or reduce defenses.

### 2. Validate the actor
- Confirm whether the actor is:
  - a normal IAM administrator
  - an application/service principal
  - a newly suspicious identity
  - an actor with no expected identity-admin role
- Review recent sign-ins and privilege usage for that identity.

### 3. Review the target object
- Determine whether the target is:
  - a privileged user
  - a high-value application
  - Conditional Access policy
  - service principal
  - authentication configuration object
- Prioritize changes affecting broad tenant security controls.

### 4. Correlate with related cloud abuse
Look for:
- risky sign-ins
- mailbox changes
- OAuth consent activity
- app registration
- device registration
- inbox rule abuse
- Graph or SharePoint access

### 5. Validate business context
- Check for change approvals, CAB references, or maintenance windows.
- Planned identity onboarding and certificate rotation can be valid, but should be verifiable.

## Common Benign Explanations
- Legitimate IAM administration
- Planned conditional access or application changes
- Approved identity onboarding or certificate rotation :contentReference[oaicite:13]{index=13}

## Escalate When
Escalate if:
- the actor is not expected to make identity control-plane changes
- the change weakens security or adds new credentials
- high-value policies, apps, or identities are affected
- there are related risky sign-ins or cloud-abuse indicators
- there is no supporting change-management context

## Suggested Response Actions
- Preserve the Entra audit trail and change details
- Review whether the change should be reverted immediately
- Validate actor legitimacy with identity admins
- Search for related changes by the same actor across the tenant
- Review downstream cloud abuse tied to the same identity or app
- Contain compromised identities, app credentials, or sessions as needed

## Analyst Notes
This is a high-priority cloud persistence analytic. Control-plane changes can outlast endpoint cleanup and may be the attacker’s true long-term foothold.