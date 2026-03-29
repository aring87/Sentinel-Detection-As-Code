# AzCopy or Cloud CLI Bulk Export Activity

## Goal
Identify repeated use of cloud transfer command-line tools that may indicate bulk export, synchronization, or exfiltration from an endpoint.

## Why This Alert Matters
Cloud transfer tools such as AzCopy, AWS CLI, and gsutil are powerful and legitimate, but they can also be used to move large amounts of data out of the environment quickly. Attackers may abuse these tools because they support sanctioned cloud services and can blend into engineering or DevOps workflows. This guide is based on a rule that looks for repeated cloud-transfer CLI execution with copy, sync, upload, or storage-related arguments. :contentReference[oaicite:12]{index=12}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for execution of:
- `azcopy.exe`
- `azcopy`
- `aws.exe`
- `aws`
- `gsutil.exe`
- `gsutil`

It looks for command-line content such as:
- `copy`
- `sync`
- `cp`
- `s3://`
- `blob.core.windows.net`
- `storage`
- `gs://`
- `download`
- `upload`

It triggers on repeated usage over time from the same device and account context. :contentReference[oaicite:13]{index=13}

## Likely ATT&CK Mapping
- **T1537** – Transfer Data to Cloud Account
- **T1567** – Exfiltration Over Web Service

## Initial Triage Questions
1. Which cloud CLI was used?
2. What source and destination paths or buckets were referenced?
3. Was the activity copy, sync, upload, or download?
4. Is the user or device expected to use cloud transfer tools?
5. Did the transfer involve sensitive data, backups, or project content?
6. Were there storage permission changes or archive creation nearby?
7. Is this normal engineering behavior or suspicious bulk movement?

## Key Fields To Review
- `DeviceName`
- `InitiatingProcessAccountName`
- `FileName`
- `ExecCount`
- `Commands`
- `FirstSeen`
- `LastSeen`

## Investigation Steps

### 1. Identify the transfer tool and pattern
- Determine whether the tool was AzCopy, AWS CLI, or gsutil.
- Review the command lines for:
  - copy
  - sync
  - upload
  - download
  - bucket or blob references
- Determine whether the commands imply bulk movement.

### 2. Review destination context
- Identify the destination account, bucket, blob container, or cloud storage location.
- Determine whether the destination is:
  - enterprise-managed
  - personal
  - third-party
  - unknown
- Review whether the destination is expected for that user or team.

### 3. Assess the volume and cadence
- Check how many executions occurred and over what period.
- Repeated CLI invocations may indicate automated bulk export or sync behavior rather than a one-off transfer.

### 4. Correlate with prior staging
Look for:
- archive creation
- mass file access
- collection from user data paths
- bulk cloud-storage uploads
- unusual sign-ins
- permission or public-access changes

### 5. Validate legitimate engineering or admin context
- Confirm whether the host is used for:
  - DevOps
  - cloud administration
  - backup or restore
  - migration
- If the device is a standard user endpoint, this activity deserves greater scrutiny.

## Common Benign Explanations
- Approved cloud migration or backup operations
- Engineering or DevOps workflows using cloud transfer tools
- Authorized bulk restore or synchronization tasks :contentReference[oaicite:14]{index=14}

## Escalate When
Escalate if:
- the destination is unapproved or unknown
- the user is not expected to use the cloud CLI involved
- command lines show bulk export, sync, or staging
- the device also shows archive creation or collection behavior
- there are suspicious storage permission changes nearby

## Suggested Response Actions
- Preserve the full CLI commands and timestamps
- Review the cloud destination and identity context
- Validate whether the destination tenant, bucket, or storage account is approved
- Search for the same CLI usage on other endpoints
- Coordinate with cloud admins to review object access and transfer logs
- Contain the host if malicious bulk export is confirmed

## Analyst Notes
This is a strong exfiltration analytic in engineering-heavy environments, but it needs context. The key question is whether the tool use is expected on that host by that user and whether the destination is enterprise-controlled.