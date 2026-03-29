# Suspicious External Remote Service Sign-In

## Goal
Identify successful external sign-ins to remote access or administrative services that may represent abuse of externally exposed services.

## Why This Alert Matters
External remote access is a common entry point for attackers, especially when identities are compromised or security controls are weak. Successful sign-ins to remote access or administrative services from public IP space can indicate valid-account abuse, external service exploitation, or unauthorized remote access. This guide is based on a rule that surfaces successful public-IP sign-ins to services such as Azure Portal, Windows Sign In, VPN, or Remote Desktop. :contentReference[oaicite:18]{index=18}

## What the Detection Is Looking For
This detection reviews `SigninLogs` for:
- successful sign-ins
- public, non-private source IPs
- application names associated with remote access or administrative services such as:
  - `Azure Portal`
  - `Windows Sign In`
  - `VPN`
  - `Remote Desktop`

It surfaces sign-in time, user, IP, app, location, conditional access status, risk level, and user agent. :contentReference[oaicite:19]{index=19}

## Likely ATT&CK Mapping
- **T1133** – External Remote Services

## Initial Triage Questions
1. Which service was accessed?
2. Is the sign-in source location or IP normal for the user?
3. Does the IP map to expected VPN, cloud, or contractor infrastructure?
4. Was the sign-in protected by Conditional Access or MFA?
5. Does the user normally access the service externally?
6. Were there nearby device registrations, mailbox access, or remote endpoint sessions?
7. Is there evidence of valid-account abuse or phishing before the sign-in?

## Key Fields To Review
- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `AppDisplayName`
- `Location`
- `ConditionalAccessStatus`
- `RiskLevelAggregated`
- `UserAgent`

## Investigation Steps

### 1. Validate the sign-in source
- Review the source IP, geolocation, ASN, and hosting provider.
- Determine whether the source is:
  - corporate VPN
  - known cloud provider
  - contractor or partner infrastructure
  - suspicious or newly observed
- Compare against the user’s normal sign-in baseline.

### 2. Review access controls
- Check whether MFA, Conditional Access, or device requirements were enforced.
- Determine whether the authentication was unusually weak or bypassed normal controls.

### 3. Assess service context
- Identify whether the service accessed was:
  - Azure Portal
  - Windows sign-in
  - VPN
  - Remote Desktop
- Determine whether the user is expected to access that service externally.

### 4. Correlate with related activity
Look for:
- device registration
- mailbox access
- Quick Assist or RMM use
- risky sign-ins
- app-consent changes
- endpoint logons
- unusual data access afterward

### 5. Validate business context
- Confirm whether the user was:
  - traveling
  - working remotely
  - performing approved admin work
- If the sign-in source and service use are inconsistent, escalate.

## Common Benign Explanations
- Authorized travel or remote administration
- Known VPN gateways or managed remote services
- Contractor or support access from approved locations :contentReference[oaicite:20]{index=20}

## Escalate When
Escalate if:
- the source IP or location is unusual or suspicious
- the user is not expected to access the service externally
- Conditional Access or risk context is concerning
- the sign-in is followed by device registration, mailbox access, or endpoint remote activity
- the identity shows other phishing or valid-account abuse indicators

## Suggested Response Actions
- Preserve the sign-in record and related identity telemetry
- Validate the sign-in directly with the user if appropriate
- Review Conditional Access, MFA, and device context
- Search for similar sign-ins from the same IP or actor
- Revoke sessions or force password reset if compromise is likely
- Coordinate with identity and endpoint teams for broader validation

## Analyst Notes
This is a foundational initial-access analytic for identity-driven attacks. It is strongest when paired with risky sign-ins, phishing indicators, or unusual follow-on activity in cloud and endpoint logs.