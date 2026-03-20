# Device Code Sign-In Followed by Device Registration

## Goal
Identify suspicious device code authentication followed by registration of a new device, which may indicate attacker-controlled device enrollment and token abuse.

## Why This Alert Matters
Device code phishing can allow an attacker to obtain access tokens without stealing a password directly. If that access is then used to register a new device, it may support long-term access, token persistence, or Privileged Refresh Token-related abuse.

## What the Detection Is Looking For
This detection looks for:
- a successful device code sign-in
- followed within a short time window by a device registration event
- for the same user

## Initial Triage Questions
1. Did the user expect a device code login prompt?
2. Is the newly registered device known and corporate-managed?
3. Did the sign-in originate from an unusual IP, geography, or proxy?
4. Was there follow-on access to email, files, Teams, or cloud apps?

## Key Evidence To Review
- user UPN
- device code sign-in time
- source IP address
- app used during the sign-in
- registered device name and object ID
- later sign-ins from the new device

## Investigation Steps
1. Confirm the device code sign-in was successful and review its source context.
2. Validate the newly registered device with the user, endpoint team, or asset inventory.
3. Check whether the device is managed, compliant, and expected.
4. Review follow-on cloud activity such as Graph, mailbox, OneDrive, SharePoint, or Teams access.
5. Look for related OAuth consent, inbox rule creation, or risky sign-ins.

## Common Benign Explanations
- approved device enrollment
- legitimate user setup of a new corporate device
- IT-guided onboarding workflows

## Escalate When
Escalate if:
- the user denies the device code login
- the device is unknown or unmanaged
- the source IP is suspicious
- follow-on access to mail, files, or Teams occurs unexpectedly

## Suggested Response Actions
- revoke active sessions and refresh tokens
- disable or remove the suspicious device registration if confirmed malicious
- require credential reset and MFA review
- investigate nearby mailbox, file, and Teams activity

## Analyst Notes
This is a high-priority identity alert because it can indicate an attacker moved from phishing to durable cloud access.