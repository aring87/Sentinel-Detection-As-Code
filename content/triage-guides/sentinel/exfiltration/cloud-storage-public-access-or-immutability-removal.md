# Cloud Storage Public Access or Immutability Removal

## Goal
Identify cloud storage configuration changes that make data easier to expose, export, or destroy.

## Why This Alert Matters
Enabling public access, weakening network restrictions, or removing immutability can enable exfiltration or anti-recovery actions. These changes are especially concerning when followed by bulk transfer or deletion.

## What the Detection Is Looking For
This detection looks for:
- public access enablement
- firewall or network ACL weakening
- immutability or legal hold removal
- related cloud storage admin changes

## Initial Triage Questions
1. Was the storage change approved?
2. Who made the change?
3. What resource or container was affected?
4. Did bulk data movement or deletion follow?

## Key Evidence To Review
- actor identity
- changed property names and values
- affected storage account, bucket, or container
- follow-on AzCopy/cloud CLI use
- cloud access logs and object activity

## Investigation Steps
1. Review the exact configuration change.
2. Validate whether the actor is an authorized cloud admin.
3. Determine whether the change increased exposure or reduced recovery protection.
4. Check for subsequent file access, sync, download, or delete activity.
5. Assess whether the resource contains sensitive or regulated data.

## Common Benign Explanations
- planned migration work
- approved storage reconfiguration
- testing or controlled public sharing

## Escalate When
Escalate if:
- public access or immutability was changed unexpectedly
- the actor is not approved
- bulk transfer or deletion follows
- the affected resource contains backups or sensitive data

## Suggested Response Actions
- revert the storage control change if malicious
- review recent object access and transfer volume
- isolate compromised accounts or sessions
- notify cloud owners and IR

## Analyst Notes
This is a strong precursor alert for both exfiltration and destructive cloud activity.