# Teams External Contact Followed by Quick Assist

## Goal
Identify possible social-engineering chains in which external Teams contact or chat activity is followed by Quick Assist execution.

## Why This Alert Matters
Attackers may use Teams to impersonate IT or support staff, then move the user into Quick Assist for hands-on-keyboard access. This pattern is especially relevant in Microsoft-centric environments.

## What the Detection Is Looking For
This detection looks for:
- external or guest Teams contact activity
- followed within a short time window by Quick Assist usage
- for the same user

## Initial Triage Questions
1. Was the Teams contact internal, guest, or external?
2. Did the external party claim to be support or IT?
3. Did the user then accept a Quick Assist session?
4. Were scripts, tools, or downloads launched afterward?

## Key Evidence To Review
- Teams operation type
- external/guest indicators
- Quick Assist timing
- user account and endpoint
- follow-on endpoint activity

## Investigation Steps
1. Review the Teams contact and whether it was external or guest-originated.
2. Determine whether the user was coached into accepting remote help.
3. Review Quick Assist execution on the endpoint.
4. Check for PowerShell, batch, RMM, or download activity after the session started.
5. Validate with the user what instructions they received.

## Common Benign Explanations
- approved external collaboration
- legitimate support interactions
- vendor troubleshooting through federated Teams workflows

## Escalate When
Escalate if:
- the external contact is suspicious or unknown
- the user was convinced to accept remote access
- follow-on script or payload activity occurred
- similar events affected multiple users

## Suggested Response Actions
- notify messaging/collaboration admins
- preserve Teams interaction evidence
- isolate affected hosts if malicious activity followed
- review external chat histories for wider targeting

## Analyst Notes
This is best tuned in environments with frequent external Teams collaboration.