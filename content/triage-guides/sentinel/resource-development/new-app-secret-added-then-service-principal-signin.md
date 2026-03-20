# New App Secret Added Then Service Principal Sign-In

## Goal
Identify cases where a new application credential is added and then the service principal signs in shortly afterward.

## Why This Alert Matters
This can indicate rapid operationalization of a cloud application after credential creation. In a malicious scenario, an attacker adds a secret to a compromised or newly created app and immediately begins using it.

## What the Detection Is Looking For
This detection looks for:
- app secret or key credential creation
- followed within hours by service principal sign-in
- using the same application identity

## Initial Triage Questions
1. Was the secret addition approved?
2. Who added the credential?
3. Was the app newly created or recently modified?
4. What resources did the service principal access afterward?

## Key Evidence To Review
- app name
- app owner and initiator
- secret addition event
- service principal sign-in timing
- target resources accessed after sign-in

## Investigation Steps
1. Validate whether the app is known and managed.
2. Review who added the secret or key credential.
3. Check what the service principal accessed shortly after sign-in.
4. Determine whether the app has broad or high-risk permissions.
5. Correlate with suspicious consent, mailbox access, SharePoint activity, or unusual cloud administration.

## Common Benign Explanations
- approved app onboarding
- secret rotation
- cloud engineering maintenance

## Escalate When
Escalate if:
- the app is unknown or newly created unexpectedly
- the credential was added by an unexpected user
- the service principal immediately accessed sensitive resources
- the app overlaps with consent-phishing or mail/file access detections

## Suggested Response Actions
- disable or restrict the app if malicious
- remove the newly added credential
- review service principal access scope
- notify cloud identity owners and IR

## Analyst Notes
This is one of the strongest cloud control-plane detections when timing is tight and access begins immediately.