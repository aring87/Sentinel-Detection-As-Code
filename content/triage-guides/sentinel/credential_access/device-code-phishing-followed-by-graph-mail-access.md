# Device Code Phishing Followed by Graph Mail Access

## Goal
Identify successful device code authentication followed by Microsoft Graph mail access for the same user, which may indicate device code phishing followed by mailbox collection.

## Why This Alert Matters
Device code phishing is a modern and effective technique because it abuses a legitimate authentication flow instead of relying on traditional malware delivery. If a successful device code sign-in is followed shortly by Graph-based mailbox access, that may indicate an attacker has obtained a usable cloud session and immediately started collecting email content.

This sequence is especially important because it may represent a cloud-only intrusion path with little or no traditional endpoint malware.

## What the Detection Is Looking For
This detection correlates:

- successful `deviceCode` sign-ins from `SigninLogs`
- Microsoft Graph mail-access activity from `CloudAppEvents`

The rule looks for Graph activity such as:
- `MailItemsAccessed`
- `SearchQueryPerformed`
- `MessageBind`
- `FileDownloaded`
- `MailAccess`

The sequence is considered suspicious when Graph mail activity occurs within a short window after successful device code authentication for the same user.

## Likely ATT&CK Mapping
- **T1528** – Steal Application Access Token
- **T1114** – Email Collection

## Initial Triage Questions
1. Did the user expect a device code authentication flow?
2. What application initiated the device code sign-in?
3. What IP address was used for the sign-in?
4. How soon after the sign-in did Graph mail activity begin?
5. Did the Graph activity target the user’s own mailbox or unusual content?
6. Were there follow-on inbox rules, OAuth abuse, or exfiltration indicators?
7. Has this user shown other risky sign-ins, token abuse, or suspicious cloud behavior?

## Key Fields To Review
- `SigninTime`
- `GraphTime`
- `JoinUser`
- `SigninIP`
- `SigninApp`
- `ActionType`
- `Application`
- `RawEventData`

## Investigation Steps

### 1. Validate the device code sign-in
- Review whether the user is known to use device code authentication.
- Check the source IP, ASN, geography, and user agent context if available.
- Determine whether the sign-in application is expected.

### 2. Review the Graph mail activity
- Identify the exact mail-related operations performed.
- Determine whether the activity reflects:
  - mailbox browsing
  - search-heavy collection
  - message access
  - file or attachment download
- Review whether the mailbox activity volume is unusual for the user.

### 3. Assess the time relationship
- Confirm how quickly Graph mail activity followed the device code sign-in.
- Prioritize cases where collection began almost immediately after authentication.

### 4. Check for follow-on cloud abuse
Look for:
- inbox rule creation
- mailbox forwarding
- OAuth consent grants
- suspicious app registrations
- bulk SharePoint or OneDrive access
- external email or collaboration activity

### 5. Validate user and business context
- Confirm whether the user expected a device-code prompt.
- Determine whether the activity was part of:
  - approved mobile or TV-style login workflow
  - migration tooling
  - eDiscovery
  - mailbox administration

## Common Benign Explanations
- Legitimate device code workflows using approved Microsoft clients
- Approved administrative or eDiscovery tooling
- Lab validation or identity testing

## Escalate When
Escalate if:
- the user did not expect the device code login
- the sign-in came from a suspicious IP or unusual location
- Graph activity began immediately after authentication
- the session performed search-heavy or download-heavy mailbox access
- the account also created inbox rules, forwarding rules, or suspicious app activity
- the same user shows other phishing or token-abuse indicators

## Suggested Response Actions
- Preserve the sign-in and Graph event evidence
- Review all cloud activity tied to the same user and session window
- Revoke tokens or force reauthentication if compromise is suspected
- Investigate mailbox access scope and possible message export
- Search for the same sign-in pattern across other users
- Review related OAuth, inbox-rule, and exfiltration activity

## Analyst Notes
This is one of the stronger cloud-sequence detections because it ties a suspicious authentication pattern directly to likely mailbox collection. It is especially valuable in environments where device code phishing is a realistic threat or where cloud-only intrusions are a concern.