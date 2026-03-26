# Device Code or OAuth Authorization Abuse Against Microsoft 365

## Goal
Identify suspicious device code or OAuth-related authentication activity that may indicate phishing, token abuse, or exploitation of trusted Microsoft authentication flows.

## Why This Alert Matters
CrowdStrike highlighted abuse of legitimate authentication flows and familiar Microsoft sign-in experiences. Device code and OAuth workflows can be abused to capture user approval or obtain access without relying on direct credential theft. These attacks are difficult for users to spot because the sign-in surface can appear legitimate, and the resulting access may persist through tokens or app-based trust relationships.

## What the Detection Is Looking For
This detection reviews sign-in telemetry for:
- authentication flows such as:
  - `deviceCode`
  - `oAuth2`
- successful sign-ins involving Microsoft 365-related applications
- client or application context suggesting trusted workflow abuse

## Likely ATT&CK Mapping
- T1528 – Steal Application Access Token
- T1078 – Valid Accounts
- T1566 – Phishing
- T1550 – Use Alternate Authentication Material

## Initial Triage Questions
1. Which app or client was involved in the authorization flow?
2. Was the user expecting a device code sign-in or delegated OAuth approval?
3. Did the sign-in originate from a new IP, geography, ASN, or device?
4. Was the flow followed by mailbox access, SharePoint access, or other sensitive cloud activity?
5. Were there related app consent, MFA, or mailbox rule changes?

## Key Fields To Review
- TimeGenerated
- UserPrincipalName
- AppDisplayName
- AuthenticationProtocol
- ResultType
- IPAddress
- ClientAppUsed
- DeviceDetail
- LocationDetails
- ConditionalAccessStatus

## Investigation Steps
### 1. Validate the authentication flow
- Confirm whether the event used:
  - device code
  - delegated OAuth
  - another token-based workflow
- Determine whether the application is expected in the environment.

### 2. Review the user context
- Confirm whether the user normally uses the app or flow.
- Check whether the user recently reported:
  - suspicious prompts
  - MFA fatigue
  - login confusion
  - support-themed contact attempts

### 3. Assess sign-in risk
- Review:
  - source IP
  - location
  - ASN
  - device identity
  - client application
- Determine whether the sign-in looks anomalous relative to the user’s baseline.

### 4. Correlate with post-authentication activity
Look for:
- mailbox access
- inbox rule creation
- app consent
- file access in OneDrive or SharePoint
- new MFA method registration
- privileged role use or admin operations

### 5. Validate business context
- Confirm whether the flow maps to:
  - legitimate device onboarding
  - Intune enrollment
  - approved productivity apps
  - known internal workflows
- Verify that the exact app, timing, and device make sense.

## Common Benign Explanations
- Device onboarding
- Approved OAuth application use
- Intune or Microsoft 365 enrollment workflows
- Expected delegated app authorization

## Escalate When
Escalate if:
- the user did not expect the authorization flow
- the sign-in came from unusual infrastructure
- the same user or app was followed by mailbox or tenant changes
- high-risk applications or broad delegated permissions were involved
- multiple suspicious cloud actions occurred soon after the sign-in

## Suggested Response Actions
- preserve the sign-in and token-related evidence
- review app consent and session history for the user
- revoke sessions or tokens if abuse is suspected
- investigate mailbox, SharePoint, and admin actions following the sign-in
- notify the identity team if trusted-flow abuse is confirmed

## Analyst Notes
These alerts are often subtle and require sequence thinking. The strongest cases connect a suspicious authorization flow to unusual post-authentication activity rather than treating the sign-in as an isolated event.
