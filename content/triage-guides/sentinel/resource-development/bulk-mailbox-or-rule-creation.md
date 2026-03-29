# Bulk Mailbox or Inbox Rule Creation Activity

## Goal
Identify bursts of mailbox or inbox-rule creation activity that may support phishing infrastructure setup, tenant staging, or suspicious mail workflow manipulation.

## Why This Alert Matters
Attackers preparing cloud-based phishing, collection, or persistence workflows may create or modify multiple mailboxes or inbox rules in a short period. Although these actions can be part of legitimate migration or administration work, bursty mailbox or rule creation can also indicate staging for forwarding, hiding, or redirecting mail at scale. This guide is based on a rule that reviews `OfficeActivity` for repeated `New-InboxRule`, `Set-InboxRule`, or `New-Mailbox` activity within a 30-minute window. :contentReference[oaicite:6]{index=6}

## What the Detection Is Looking For
This detection reviews `OfficeActivity` for:
- `New-InboxRule`
- `Set-InboxRule`
- `New-Mailbox`

It summarizes:
- total activity count
- operations involved
- user responsible
- 30-minute time window

The rule triggers when the activity count is high enough to suggest bulk or staged behavior. :contentReference[oaicite:7]{index=7}

## Likely ATT&CK Mapping
- **T1585** – Establish Accounts
- **T1098** – Account Manipulation

## Initial Triage Questions
1. Were mailboxes created, inbox rules created, or both?
2. Which user initiated the changes?
3. Is the initiator an authorized Exchange or M365 administrator?
4. Do the created rules support forwarding, hiding, or deletion behavior?
5. Was the activity tied to migration, onboarding, or suspicious staging?
6. Were there related suspicious sign-ins, app registrations, or mailbox-access spikes?
7. Did the changes affect high-value or shared mailboxes?

## Key Fields To Review
- `UserId`
- `TimeGenerated`
- `ActivityCount`
- `Operations`

## Investigation Steps

### 1. Review the operation mix
- Determine whether the burst involved:
  - mailbox creation
  - inbox rule creation
  - inbox rule modification
- Large numbers of inbox-rule changes may be more suspicious than mailbox creation alone.

### 2. Validate the initiating actor
- Confirm whether the user is:
  - Exchange admin
  - automation account
  - helpdesk or migration admin
  - unexpected business user
- Review whether the actor normally performs tenant-wide mail operations.

### 3. Inspect for concealment or routing behavior
- If inbox rules are involved, determine whether they:
  - forward messages
  - redirect mail
  - hide messages in folders
  - mark items as read
  - delete content
- Those patterns may shift the event toward persistence or collection concerns.

### 4. Correlate with related cloud abuse
Look for:
- risky sign-ins
- app registration or app secret creation
- consent abuse
- Graph mail access
- suspicious forwarding rules
- bulk SharePoint or OneDrive access

### 5. Validate legitimate operational context
- Confirm whether the activity aligns with:
  - mail migration
  - tenant onboarding
  - support workflow setup
  - approved routing changes
- If yes, document the context for tuning.

## Common Benign Explanations
- Mail migration activity
- Bulk administrative mailbox changes
- Approved mailbox routing or tenant onboarding work :contentReference[oaicite:8]{index=8}

## Escalate When
Escalate if:
- the initiator is not expected to make mail admin changes
- multiple inbox rules are created or modified in a short window
- the rules support forwarding, hiding, or deletion
- there are related suspicious sign-ins or app-registration events
- high-value users or shared mailboxes are affected

## Suggested Response Actions
- Preserve the audit events and affected user list
- Review the created mailboxes and inbox rules directly
- Validate changes with Exchange or M365 admins
- Search for similar burst activity by the same actor elsewhere
- Revert unauthorized rules or provisioning if necessary
- Investigate related cloud and identity activity

## Analyst Notes
This is a mixed resource-development and persistence analytic. It is strongest when bursty mail changes are paired with suspicious sign-ins, forwarding behavior, or tenant-staging activity.