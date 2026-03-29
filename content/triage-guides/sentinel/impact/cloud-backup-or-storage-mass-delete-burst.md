# Cloud Backup or Storage Mass Delete Burst

## Goal
Identify bursts of cloud storage or backup deletion activity that may indicate destructive cloud impact or anti-recovery actions.

## Why This Alert Matters
Attackers targeting cloud environments may delete storage accounts, snapshots, buckets, vaults, or backup-related resources to destroy data or eliminate recovery options. A burst of destructive cloud admin actions is especially concerning when it affects backup or storage resources and when it follows identity compromise or suspicious cloud control-plane changes. This guide is based on a rule that summarizes deletion activity across Azure and cloud app telemetry over short time windows. :contentReference[oaicite:8]{index=8}

## What the Detection Is Looking For
This detection reviews:
- `AzureActivity`
- `CloudAppEvents`

It looks for repeated deletion-related activity involving:
- storage accounts
- recovery vaults
- snapshots
- buckets
- backup vaults

The rule triggers on bursts of deletion activity within a 30-minute window. :contentReference[oaicite:9]{index=9}

## Likely ATT&CK Mapping
- **T1485** – Data Destruction
- **T1490** – Inhibit System Recovery

## Initial Triage Questions
1. What cloud resources were deleted?
2. Were snapshots, backup vaults, or storage accounts involved?
3. Is the actor expected to perform destructive cloud administration?
4. Did the activity occur during decommissioning or approved cleanup?
5. Were public-access, immutability, or credential-abuse events seen beforehand?
6. Is there evidence of extortion, ransomware, or anti-recovery behavior?
7. Did the actor also access or export data before deletion?

## Key Fields To Review
- `TimeGenerated`
- `Actor`
- `Scope`
- `Source`
- `DeleteCount`
- `Ops`

## Investigation Steps

### 1. Identify what was deleted
- Determine whether the activity affected:
  - storage accounts
  - snapshots
  - recovery vaults
  - buckets
  - backup-related resources
- Prioritize deletion of backup and recovery resources.

### 2. Validate the actor
- Confirm whether the actor is:
  - an authorized cloud admin
  - a service principal
  - a suspicious or recently risky identity
- Review recent sign-ins, credential use, and privilege changes for the actor.

### 3. Assess the rate and scope
- Review how many delete operations occurred.
- Determine whether the activity was targeted cleanup or bulk destructive action across multiple resources.

### 4. Correlate with earlier cloud abuse
Look for:
- public access changes
- immutability or legal hold removal
- app-secret creation
- suspicious app registrations
- risky sign-ins
- bulk download or bulk export activity

### 5. Validate change-management context
- Confirm whether the activity was part of:
  - planned decommissioning
  - lifecycle automation
  - retention cleanup
  - approved teardown work
- If there is no valid business context, escalate immediately.

## Common Benign Explanations
- Planned decommissioning or cleanup work
- Approved lifecycle automation
- Authorized cloud retention or teardown workflows :contentReference[oaicite:10]{index=10}

## Escalate When
Escalate if:
- snapshots, backup vaults, or recovery resources were deleted in bulk
- the actor is not expected to perform destructive cloud administration
- the deletions follow public-access or immutability weakening
- the account also shows suspicious sign-in or credential-abuse activity

## Suggested Response Actions
- Preserve the cloud audit trail immediately
- Validate whether deleted resources can be recovered
- Coordinate with cloud and backup admins
- Review the actor’s privileges, sign-ins, and related changes
- Contain compromised identities if needed
- Search for similar deletion bursts in other subscriptions or tenants

## Analyst Notes
This is a high-priority cloud impact alert. Bulk deletion of backup or storage resources may indicate extortion, destructive intent, or preparation to prevent recovery.