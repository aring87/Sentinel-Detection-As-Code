# Triage Guide: VMware vCenter VMDK Attach-Detach Activity Potentially Related to NTDS Theft

## What this detects
VMware activity suggesting VMDK detach/attach, unmanaged VM creation, or suspicious reconfiguration around domain controller disks.

## Why it matters
This can indicate offline theft of ntds.dit and the SYSTEM hive from an unmanaged VM.

## Immediate questions
1. Which administrator or service account performed the action?
2. Was a DC VMDK detached, mounted, or cloned?
3. Was a new or dormant VM powered on around the same time?
4. Were vCenter credentials recently accessed by an unusual user?

## Investigative steps
- Review raw vCenter logs around the event window.
- Identify the source account, source IP, and affected VM objects.
- Confirm whether a domain controller was shut down or reconfigured.
- Check for creation or reactivation of unmanaged VMs.
- Review AD-related follow-on activity, including DCSync, secretsdump, or privileged auth.

## Escalation indicators
- Domain controller VMDK involved
- New or decommissioned VM used as mount host
- Same actor also touched PAM, VDI, or SSO systems
- Secrets-dumping tools appear shortly after

## Likely false positives
- Planned maintenance
- Disaster recovery testing
- Backup, restore, or migration operations
