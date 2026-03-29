# VMware vCenter VMDK Attach-Detach Activity Potentially Related to NTDS Theft

## Goal
Identify suspicious VMware vCenter activity involving VMDK attach-detach patterns that may support offline theft of `ntds.dit` or other credential material from virtualized domain controllers.

## Why This Alert Matters
Attackers with vCenter or virtualization access can bypass traditional endpoint defenses by detaching a domain controller disk, attaching it to another VM, and extracting `ntds.dit` and related registry hives offline. This can allow credential dumping without directly running tools on the monitored domain controller.

This behavior is especially important because it can indicate deep infrastructure compromise, credential theft, and defense evasion at the virtualization layer.

## What the Detection Is Looking For
This detection reviews `VMware_CL` for suspicious vCenter activity involving:
- VMDK references
- attach and detach operations
- VM reconfiguration
- VM creation or registration
- VM power-on activity

It assigns a suspicion score based on the presence of behaviors such as:
- `detach`
- `attach`
- `vmdk`
- `createvm`
- `registervm`
- `poweronvm`

The rule triggers when multiple suspicious indicators appear together.

## Likely ATT&CK Mapping
- **T1003.003** – OS Credential Dumping: NTDS
- **T1562** – Impair Defenses

## Initial Triage Questions
1. Which actor performed the VMDK and VM changes?
2. Did the affected VMDK belong to a domain controller or identity-critical system?
3. Was a new or unmanaged VM created or powered on around the same time?
4. Was the disk attached to another VM unexpectedly?
5. Is the activity part of approved backup, migration, or recovery work?
6. Were there related signs of registry hive access, credential dumping, or abnormal admin activity?
7. Is the actor normally authorized to perform vCenter disk operations?

## Key Fields To Review
- `TimeGenerated`
- `Computer`
- `RawData`
- `SuspicionScore`

## Investigation Steps

### 1. Identify the VMware operation sequence
- Review the raw event data for the order of actions.
- Determine whether the sequence included:
  - VMDK detach
  - VMDK attach
  - VM creation or registration
  - VM power-on
- Reconstruct the affected VM and destination VM if possible.

### 2. Determine whether a domain controller was involved
- Identify whether the VMDK belonged to:
  - a domain controller
  - an Entra Connect or identity server
  - another system containing credential-sensitive data
- Prioritize cases involving AD infrastructure.

### 3. Validate the actor and maintenance context
- Confirm whether the operator is a legitimate virtualization administrator.
- Review whether the activity aligns with:
  - backup
  - migration
  - disaster recovery
  - maintenance windows
- If no valid maintenance context exists, treat the alert as high priority.

### 4. Search for offline theft indicators
Look for:
- unmanaged VM creation
- temporary utility VM creation
- registry hive or `ntds.dit` access
- unusual file copy activity
- suspicious mounts or exports
- subsequent credential use in the environment

### 5. Correlate with credential abuse
- Check for:
  - new privileged logons
  - DCSync
  - password resets
  - Kerberos abuse
  - lateral movement
  - suspicious service or task creation after the vCenter activity

## Common Benign Explanations
- Legitimate VMware recovery operations
- Approved migration projects
- Backup or snapshot-related maintenance
- Disaster recovery testing
- Planned infrastructure work by virtualization admins

## Escalate When
Escalate if:
- the affected VMDK belonged to a domain controller
- a new or unmanaged VM was created during the sequence
- attach-detach behavior occurred without approved maintenance
- the actor is not a normal virtualization administrator
- follow-on credential abuse or domain activity is observed
- the activity appears designed to avoid endpoint controls

## Suggested Response Actions
- Preserve the relevant vCenter and VMware logs
- Identify all VMs and disks involved in the operation chain
- Review whether sensitive AD files or hives were accessed offline
- Limit or revoke suspicious administrative access to vCenter
- Investigate follow-on domain compromise indicators immediately
- Coordinate with virtualization and identity teams for containment

## Analyst Notes
This is a high-value infrastructure-level credential-access detection. It may indicate an attacker has moved beyond normal endpoint tradecraft and is operating at the virtualization layer to bypass traditional defenses. Treat this seriously, especially when domain controllers are involved.