# Device Code Sign-In Followed by Device Registration

## Goal
Identify successful device code authentication followed closely by new device registration activity for the same user, which may indicate device code phishing followed by actor-controlled device enrollment.

## Why This Alert Matters
Device code phishing is dangerous because it abuses a legitimate authentication workflow and can give an attacker usable access without traditional malware delivery. If a successful device code sign-in is followed shortly by device registration, that may indicate the attacker is establishing a more durable foothold by enrolling a device under the compromised identity. This guide is based on a rule that correlates successful device-code sign-ins with follow-on device registration activity in cloud telemetry. :contentReference[oaicite:6]{index=6}

## What the Detection Is Looking For
This detection correlates:
- successful `deviceCode` sign-ins from `SigninLogs`
- new device registration activity associated with `Device Registration Service` from `CloudAppEvents`

It joins on the user and looks for registration activity occurring within a short window after successful device-code authentication. The rule also surfaces:
- source IP
- application name
- correlation ID
- device name
- device object ID :contentReference[oaicite:7]{index=7}

## Likely ATT&CK Mapping
- **T1566** – Phishing
- **T1528** – Steal Application Access Token

## Initial Triage Questions
1. Did the user expect a device code prompt?
2. What application was used during the device-code sign-in?
3. What source IP and geography were involved?
4. Was the newly registered device expected, managed, and corporate-owned?
5. How quickly did registration follow authentication?
6. Did the same user show mailbox, SharePoint, Teams, or Graph activity afterward?
7. Is this user normally involved in device enrollment workflows?

## Key Fields To Review
- `SigninTime`
- `RegistrationTime`
- `JoinUser`
- `IPAddress`
- `AppDisplayName`
- `DeviceName`
- `DeviceObjectId`
- `Application`
- `CorrelationId`
- `RawEventData`

## Investigation Steps

### 1. Review the device-code sign-in
- Confirm the sign-in was successful.
- Review the source IP, location, ASN, proxy use, and app context.
- Determine whether the user has any history of legitimate device-code authentication.

### 2. Review the device registration
- Identify the registered device name and object ID.
- Determine whether the device is:
  - known
  - corporate-managed
  - newly observed
  - suspiciously named
- Check whether the registration fits normal onboarding or identity workflows.

### 3. Assess the sequence timing
- Confirm how soon the registration followed the sign-in.
- Very short timing between device-code auth and registration can increase suspicion.

### 4. Check for follow-on cloud abuse
Look for:
- Graph mail access
- inbox rule creation
- SharePoint or OneDrive access
- Teams activity
- app consent or app registration
- unusual downloads or bulk data access

### 5. Validate legitimate enrollment context
- Confirm whether the user was enrolling a known corporate device.
- Check with endpoint or Entra admins for expected registration records.
- If no valid enrollment context exists, escalate.

## Common Benign Explanations
- Legitimate device code enrollment scenarios
- Approved device registration workflows
- Lab validation of device registration flows :contentReference[oaicite:8]{index=8}

## Escalate When
Escalate if:
- the user did not expect the device-code prompt
- the device registration is unknown or unmanaged
- the sign-in originated from unusual or suspicious infrastructure
- the same user shows mailbox, Teams, or SharePoint abuse afterward
- there is no approved enrollment context for the event sequence

## Suggested Response Actions
- Preserve the sign-in and registration evidence
- Review and, if necessary, revoke suspicious sessions or tokens
- Validate the registered device with Entra and endpoint teams
- Investigate follow-on cloud activity by the same identity
- Search for similar device-code-plus-registration sequences across users
- Contain the account if broader compromise is suspected

## Analyst Notes
This is a strong cloud initial-access and foothold-establishment analytic. It is especially valuable because it can surface cloud-only compromise where the attacker quickly moves from phishing into device-associated persistence.