# Cloud Storage Public Access or Immutability Removal

## Goal
Identify cloud storage configuration changes that may enable exfiltration or weaken recovery protections before destructive activity.

## Why This Alert Matters
Attackers may change storage settings to make data easier to exfiltrate or easier to destroy later. Examples include enabling public access, weakening firewall rules, removing immutability protections, or deleting legal holds. These changes can support both exfiltration and impact. This guide is based on a rule that looks for cloud administrative activity involving storage-account writes, public-access changes, immutability changes, and similar control-plane modifications across Azure and cloud app telemetry. :contentReference[oaicite:15]{index=15}

## What the Detection Is Looking For
This detection reviews:
- `AzureActivity`
- `CloudAppEvents`

It looks for storage-related administrative activity involving:
- public access
- container or bucket ACL changes
- network ACL changes
- firewall weakening
- immutability policy changes
- legal hold changes
- deletion of immutability protections :contentReference[oaicite:16]{index=16}

## Likely ATT&CK Mapping
- **T1567** – Exfiltration Over Web Service
- **T1485** – Data Destruction

## Initial Triage Questions
1. What exact storage configuration change occurred?
2. Did the actor enable public access, weaken firewall controls, or remove immutability?
3. Was the actor authorized to perform storage administration?
4. Did the change affect high-value buckets, containers, or backup locations?
5. Did bulk access or transfer activity follow the change?
6. Was the change part of a planned migration or administration action?
7. Were there preceding risky sign-ins, secret access, or app abuse?

## Key Fields To Review
- `TimeGenerated`
- `SourceTable`
- `Actor`
- `ResourceGroup`
- `ResourceProvider`
- `Operation`
- `Details`
- `Status`
- `Application`

## Investigation Steps

### 1. Identify the control-plane change
- Determine whether the modification involved:
  - public access enablement
  - bucket or container ACL changes
  - network ACL or firewall weakening
  - immutability removal
  - legal hold removal
- Clarify whether the change would make data easier to access externally or easier to destroy.

### 2. Validate the affected storage resource
- Identify the specific storage account, container, bucket, or vault affected.
- Determine whether the resource contains:
  - business data
  - backups
  - logs
  - regulated or high-value content

### 3. Review the actor and access path
- Confirm whether the actor is an authorized storage or cloud administrator.
- Determine whether the action came from:
  - a normal admin account
  - an app or service principal
  - a suspicious or newly risky identity
- Review the identity’s recent sign-in history and privilege use.

### 4. Check for follow-on activity
Look for:
- AzCopy or cloud CLI usage
- bulk uploads or downloads
- backup deletion
- data export
- risky sign-ins
- app secret creation
- public or anonymous access to newly exposed resources

### 5. Validate change-management context
- Check CAB, maintenance, or migration records.
- Planned public-sharing changes and retention-policy work may be valid, but must still be verified.

## Common Benign Explanations
- Approved storage administration changes
- Planned migrations or controlled public-sharing changes
- Authorized backup retention or legal hold modifications :contentReference[oaicite:17]{index=17}

## Escalate When
Escalate if:
- public access was enabled unexpectedly
- immutability or legal hold was removed without change approval
- the affected resource contains backups or sensitive data
- the actor is not expected to modify storage controls
- data access or transfer followed the configuration change

## Suggested Response Actions
- Preserve the cloud admin event trail
- Verify the storage setting changes directly in the platform
- Revert unauthorized public access or immutability changes
- Review object access and transfer history after the change
- Investigate the actor’s identity for broader compromise
- Coordinate with cloud and storage administrators for containment

## Analyst Notes
This is both an exfiltration and impact analytic. It is especially important when storage controls are changed shortly before large data movement or backup destruction.