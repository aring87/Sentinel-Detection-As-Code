# Bulk Mailbox or Rule Creation

## Goal
Identify rapid creation of inbox rules or mailboxes that may indicate staging of phishing infrastructure, account abuse, or malicious mail-routing behavior.

## Why This Alert Matters
Attackers and insider threats can use inbox rules and mailbox creation to support phishing infrastructure, redirect communications, hide messages, or prepare newly compromised accounts for further abuse. A burst of rule or mailbox changes in a short period is more suspicious than a single administrative action, especially outside of planned migrations. :contentReference[oaicite:7]{index=7}

## What the Detection Is Looking For
This detection reviews `OfficeActivity` for:
- `New-InboxRule`
- `Set-InboxRule`
- `New-Mailbox`

It summarizes activity by `UserId` in 30-minute windows and alerts when at least 5 relevant operations occur. :contentReference[oaicite:8]{index=8}

## Likely ATT&CK Mapping
- T1585 – Establish Accounts
- T1586 – Compromise Accounts :contentReference[oaicite:9]{index=9}

## Initial Triage Questions
1. What rules or mailboxes were created or changed?
2. Is the initiator an authorized Exchange or M365 administrator?
3. Were the rules forwarding, deleting, hiding, or redirecting messages?
4. Was this part of a legitimate migration or bulk administrative change?
5. Were there suspicious sign-ins, phishing events, or app registrations nearby?

## Key Fields To Review
- UserId
- TimeGenerated
- Operation
- ActivityCount
- Operations

## Investigation Steps
### 1. Validate the burst
- Confirm the number of mailbox/rule operations in the 30-minute window.
- Determine whether the activity involved:
  - mostly inbox rules
  - mostly mailbox creation
  - a mixture of both

### 2. Review the specific rules or mailbox changes
- Inspect created or modified inbox rules for:
  - forwarding to external addresses
  - deleting or moving messages
  - hiding emails from the inbox
  - suspicious keyword-based filtering
- Review new mailbox purpose and ownership.

### 3. Review initiator context
- Determine whether the initiator is an approved Exchange administrator.
- Check for recent suspicious sign-ins, impossible travel, device-code abuse, or external remote-service sign-ins.

### 4. Correlate with related email or cloud activity
Check for:
- suspicious domain click spikes
- phishing campaigns
- app registration or consent changes
- mailbox access anomalies
- external forwarding behavior

### 5. Validate business explanation
- Determine whether there was a mail migration, onboarding wave, or planned admin change that explains the burst.

## Common Benign Explanations
- Mail migration activity
- Bulk administrative mailbox changes
- Approved mail-routing changes during maintenance windows :contentReference[oaicite:10]{index=10}

## Escalate When
Escalate if:
- inbox rules forward to unapproved external addresses
- the initiator is not an authorized admin
- mailbox creation or rule changes coincide with suspicious sign-ins
- rules appear designed to hide attacker activity
- the burst is unexplained by legitimate operations

## Suggested Response Actions
- preserve the affected mailbox and rule details
- disable or remove malicious inbox rules
- review mailbox audit history and sign-ins for the initiator
- notify IR and messaging/Exchange administrators
- search for the same rule patterns across other mailboxes

## Analyst Notes
This guide is especially useful for detecting resource-development behavior that supports phishing or post-compromise email abuse. It becomes even stronger when paired with suspicious sign-ins or click/campaign telemetry.