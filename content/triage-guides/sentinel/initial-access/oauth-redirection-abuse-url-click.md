# OAuth Redirection Abuse URL Click

## Goal
Identify suspicious OAuth authorization links clicked by users where parameters suggest redirection abuse or attacker-controlled redirect handling.

## Why This Alert Matters
Attackers can abuse OAuth authorization flows to deliver trusted-looking login prompts that ultimately redirect users toward malicious infrastructure, token theft, staged downloads, or app-consent abuse. A suspicious OAuth click can be an early warning sign of phishing or authorization-based social engineering before follow-on endpoint activity occurs. This guide is based on a rule that looks for suspicious OAuth-style URL parameters in clicked links. :contentReference[oaicite:12]{index=12}

## What the Detection Is Looking For
This detection reviews `UrlClickEvents` for clicked-through or allowed URLs where the URL chain includes:
- Microsoft login or OAuth authorization endpoints
- `prompt=none`
- `response_type=code`
- `redirect_uri=`
- `invalid_scope`
- `scope=`

It surfaces the clicked URL, URL chain, action type, user, and associated message ID for review. :contentReference[oaicite:13]{index=13}

## Likely ATT&CK Mapping
- **T1566.002** – Phishing: Spearphishing Link

## Initial Triage Questions
1. What exact OAuth or Microsoft login URL was clicked?
2. What redirect target or redirect URI was embedded?
3. Did the user expect the authorization flow?
4. Did the link come from email, collaboration, e-signature, or meeting lure content?
5. Was the redirect domain attacker-controlled or newly observed?
6. Did the user later show device-code sign-ins, app consent, or browser downloads?
7. Is the click consistent with legitimate developer or integration testing?

## Key Fields To Review
- `Timestamp`
- `AccountUpn`
- `ActionType`
- `Url`
- `UrlChain`
- `NetworkMessageId`

## Investigation Steps

### 1. Review the clicked URL and chain
- Inspect the full clicked URL and redirect path.
- Determine whether the parameters are:
  - normal for the app
  - suspiciously constructed
  - pointing to an unexpected redirect target
- Pay close attention to `redirect_uri` and any external domains.

### 2. Identify the lure context
- Review the associated email or collaboration message if available.
- Determine whether the message theme was:
  - document access
  - e-signature
  - meeting invite
  - support or security prompt
- User-facing context often clarifies intent.

### 3. Check for follow-on abuse
Look for:
- device-code sign-ins
- risky sign-ins
- app consent
- Graph or mailbox activity
- browser downloads
- suspicious endpoint execution shortly after the click

### 4. Validate legitimate testing context
- Determine whether the user is a developer or admin expected to test OAuth integrations.
- Rare legitimate OAuth testing can resemble this pattern but should be verifiable.

### 5. Search for campaign scope
- Search for other users clicking similar URLs or messages.
- Review whether the same redirect target appears elsewhere in user telemetry.

## Common Benign Explanations
- Rare legitimate OAuth testing workflows
- Internal developer auth troubleshooting
- Authorized application integration testing :contentReference[oaicite:14]{index=14}

## Escalate When
Escalate if:
- the redirect target is suspicious or attacker-controlled
- the user did not expect the auth flow
- the click is followed by device-code, risky sign-in, or endpoint execution
- multiple users clicked the same lure
- there is evidence of consent or token abuse afterward

## Suggested Response Actions
- Preserve the URL click evidence and associated message context
- Review mail, browser, and sign-in telemetry for the user
- Search for the same lure across the tenant
- Revoke sessions or investigate app-consent activity if needed
- Block or investigate suspicious redirect domains
- Coordinate with messaging and identity teams for campaign response

## Analyst Notes
This is a strong early-phishing analytic in cloud-centric environments. It is often most valuable when treated as the first event in a broader cloud identity or endpoint sequence.