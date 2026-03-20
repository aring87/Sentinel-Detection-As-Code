# AzCopy or Cloud CLI Bulk Export Activity

## Goal
Identify potential bulk export or exfiltration using cloud-native transfer tools such as AzCopy, AWS CLI, or gsutil.

## Why This Alert Matters
Cloud CLI tools make it easy to move large volumes of data quickly. On endpoints where this activity is unusual, repeated use may indicate staging or bulk exfiltration.

## What the Detection Is Looking For
This detection looks for repeated execution of:
- `azcopy`
- `aws`
- `gsutil`

with command-line patterns such as:
- `copy`
- `sync`
- `cp`
- `s3://`
- `blob.core.windows.net`
- `gs://`

## Initial Triage Questions
1. Is this tool normal for the user or host?
2. Was data being uploaded, downloaded, or synchronized?
3. What cloud destination or bucket/container was involved?
4. Did this follow public-access changes, archive creation, or secret exposure?

## Key Evidence To Review
- full command lines
- user role and endpoint type
- destination bucket, blob, or cloud path
- cloud storage permission changes
- preceding archive or staging activity

## Investigation Steps
1. Determine whether the user is expected to use cloud transfer tools.
2. Review whether the activity was export, sync, or download.
3. Validate the destination as corporate, personal, or unknown.
4. Correlate with storage configuration changes and exfiltration alerts.
5. Assess whether sensitive data or backups were likely involved.

## Common Benign Explanations
- cloud migrations
- backup operations
- DevOps engineering workflows
- approved data transfer jobs

## Escalate When
Escalate if:
- the user is not expected to use the tool
- transfer volume appears high
- the destination is unusual or unauthorized
- public-access or immutability changes also occurred

## Suggested Response Actions
- preserve command lines and destination identifiers
- review cloud audit logs for object access and transfer volume
- disable credentials or sessions if malicious use is suspected
- notify data owners if sensitive data may have been transferred

## Analyst Notes
This alert gains confidence when correlated with storage access-policy changes or local staging behavior.