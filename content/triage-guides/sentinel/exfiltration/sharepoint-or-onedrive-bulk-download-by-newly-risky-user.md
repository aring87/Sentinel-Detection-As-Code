# SharePoint or OneDrive Bulk Download by Newly Risky User

## Goal
Identify high-volume SharePoint or OneDrive download activity performed by a user who recently showed risky sign-in behavior.

## Why This Alert Matters
After account compromise, attackers often collect documents from SharePoint or OneDrive. Bulk download by a newly risky user can indicate cloud collection or exfiltration.

## What the Detection Is Looking For
This detection looks for:
- a recent risky or device-code-related successful sign-in
- followed by high-volume SharePoint or OneDrive download activity
- by the same user within a short time window

## Initial Triage Questions
1. Was the sign-in suspicious or expected?
2. Is the download volume normal for the user?
3. What sites, folders, or files were involved?
4. Did the user also access mail, create rules, or grant consent?

## Key Evidence To Review
- risky sign-in timing and source
- download count
- site URLs
- object IDs or file names
- related mailbox, app, or forwarding activity

## Investigation Steps
1. Review the risky sign-in and determine whether it was expected.
2. Assess whether the download volume is unusual for the user.
3. Identify which SharePoint or OneDrive locations were accessed.
4. Determine whether the data appears sensitive or high-value.
5. Check for related mail compromise, consent abuse, or public-sharing changes.

## Common Benign Explanations
- planned migration or sync
- legitimate bulk download by project or admin staff
- new-device sync behavior

## Escalate When
Escalate if:
- the sign-in is suspicious and recent
- the download volume is unusual
- the sites contain sensitive documents
- the user also shows mailbox or app abuse

## Suggested Response Actions
- revoke sessions and review the account
- preserve cloud access records
- notify data owners for affected sites
- investigate whether files were later shared or exported elsewhere

## Analyst Notes
This is a strong cloud exfiltration signal when paired with risky sign-in or device code activity.