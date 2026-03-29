# Multiple User Device Code Sign-Ins

## Goal
Identify device code authentication across multiple users from the same source context in a short time window, which may indicate phishing and token theft activity.

## Why This Alert Matters
Device code authentication is normally a targeted and relatively infrequent workflow. When multiple different users authenticate through device code from the same source context in a short period, that can indicate phishing infrastructure, a shared malicious prompt, or attacker-driven token acquisition across several accounts. This guide is based on a rule that looks for multiple users completing device-code sign-ins from the same IP and application within a 30-minute window. :contentReference[oaicite:9]{index=9}

## What the Detection Is Looking For
This detection reviews `SigninLogs` for:
- `AuthenticationProtocol =~ "deviceCode"`

It groups results by:
- `IPAddress`
- `AppDisplayName`
- 30-minute window

The rule triggers when multiple unique users authenticate through the same device-code source context within that period. It also surfaces the user list and involved apps. :contentReference[oaicite:10]{index=10}

## Likely ATT&CK Mapping
- **T1566** – Phishing
- **T1078** – Valid Accounts

## Initial Triage Questions
1. How many users authenticated through the same source context?
2. What source IP and application were involved?
3. Is device-code auth normal in this environment?
4. Are the users related by team, location, or role?
5. Does the source IP map to expected proxy, jump-box, or identity infrastructure?
6. Were there follow-on mailbox, app-consent, or device-registration events?
7. Could this reflect a lab, onboarding, or shared test scenario?

## Key Fields To Review
- `IPAddress`
- `AppDisplayName`
- `TimeGenerated`
- `UserCount`
- `Users`
- `Apps`

## Investigation Steps

### 1. Review the shared source context
- Confirm the source IP and application involved.
- Determine whether the source represents:
  - shared proxy
  - jump box
  - lab environment
  - malicious infrastructure
- Check whether the app is one that normally uses device-code auth.

### 2. Review affected users
- Identify the users involved and whether they share:
  - location
  - department
  - project
  - timing
- Multiple unrelated users increase suspicion.

### 3. Correlate with follow-on cloud activity
Look for:
- device registration
- Graph mail access
- inbox rule creation
- risky sign-ins
- consent abuse
- SharePoint or OneDrive bulk access

### 4. Validate benign explanation
- Determine whether the activity matches:
  - test tenants
  - onboarding events
  - training labs
  - known shared authentication workflows
- If the environment rarely uses device code, the alert becomes higher value.

### 5. Check for broader campaign indicators
- Review whether users received similar lures.
- Search for related email, chat, or OAuth-click activity tied to the same time window.

## Common Benign Explanations
- Legitimate device code workflows in limited environments
- Test tenants, labs, or staged onboarding events
- Shared proxy or jump-box scenarios with known auth workflows :contentReference[oaicite:11]{index=11}

## Escalate When
Escalate if:
- multiple unrelated users authenticated through device code from the same source
- the source IP is suspicious or not expected
- the same users later show Graph access, inbox rules, or device registration
- there is evidence of a shared lure or phishing campaign

## Suggested Response Actions
- Preserve the sign-in cluster and user list
- Review linked cloud activity for each affected user
- Investigate whether the source IP is known-good or suspicious
- Search for shared lure evidence across mail, chat, or browser telemetry
- Revoke sessions or force reauthentication if compromise is likely
- Coordinate with identity and messaging teams for broader campaign review

## Analyst Notes
This is a strong cluster-style initial-access analytic. It is especially useful for spotting campaign behavior instead of one-off user compromise.