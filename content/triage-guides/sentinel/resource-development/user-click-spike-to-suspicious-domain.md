# User Click Spike to Suspicious Domain

## Goal
Identify repeated user clicks to the same destination domain that may indicate attacker-controlled infrastructure used for phishing or campaign staging.

## Why This Alert Matters
When multiple users click the same external domain repeatedly in a short period, it can indicate a coordinated lure, phishing campaign, or staging infrastructure being used against the organization. This does not prove the domain is malicious, but it can be a valuable signal for emerging campaigns, especially when the domain is newly observed or associated with suspicious mail or auth activity. This guide is based on a rule that summarizes `UrlClickEvents` by domain and day, then flags domains with repeated clicks by multiple users. :contentReference[oaicite:21]{index=21}

## What the Detection Is Looking For
This detection reviews `UrlClickEvents` where:
- `ActionType =~ "ClickAllowed"`

It extracts the domain from the clicked URL and summarizes:
- total clicks
- number of users
- daily window

The rule triggers when click volume and unique-user count cross threshold. :contentReference[oaicite:22]{index=22}

## Likely ATT&CK Mapping
- **T1583.001** – Acquire Infrastructure: Domains
- **T1566.002** – Phishing: Spearphishing Link

## Initial Triage Questions
1. What domain saw the click spike?
2. How many users clicked it, and over what time?
3. Is the domain newly observed, newly registered, or otherwise suspicious?
4. Was the domain distributed through email, collaboration, or another channel?
5. Did clicked users later show OAuth lure clicks, device-code sign-ins, or credential harvesting?
6. Is the domain a known SaaS provider, marketing campaign, or legitimate external service?
7. Does the domain appear in user reports or threat tooling?

## Key Fields To Review
- `Domain`
- `Timestamp`
- `Clicks`
- `Users`

## Investigation Steps

### 1. Review the clicked domain
- Determine whether the domain is:
  - known-good business service
  - marketing link
  - newly observed
  - newly registered
  - suspiciously named or typosquatted
- Check available reputation and internal prevalence.

### 2. Identify distribution context
- Review whether the domain appeared in:
  - email campaigns
  - Teams or collaboration messages
  - document-sharing lures
  - OAuth consent or login prompts
- Message or sender context is often decisive.

### 3. Review affected users
- Identify which users clicked the domain.
- Determine whether they share:
  - role
  - geography
  - department
  - timing
- Broad or unusual spread may indicate active campaign delivery.

### 4. Correlate with follow-on abuse
Look for:
- credential-harvesting signs
- OAuth lure clicks
- device-code sign-ins
- risky sign-ins
- suspicious browser downloads
- inbox-rule creation
- cloud data access

### 5. Validate benign explanation
- Confirm whether the domain is tied to:
  - internal campaigns
  - marketing platforms
  - newly introduced SaaS
  - legitimate external services
- If yes, document the baseline and context.

## Common Benign Explanations
- Marketing or internal campaign links
- Legitimate external services accessed by many users
- Popular SaaS domains newly introduced to the environment :contentReference[oaicite:23]{index=23}

## Escalate When
Escalate if:
- the domain is suspicious, typosquatted, or newly registered
- multiple users clicked it unexpectedly
- the campaign context suggests phishing or fake login prompts
- clicked users later show OAuth, device-code, or risky sign-in activity
- the domain appears in user reports or threat-intel tooling

## Suggested Response Actions
- Preserve the clicked domain and affected-user list
- Review associated messages, senders, and lure content
- Search for the domain across mail, browser, and sign-in telemetry
- Block or investigate the domain if warranted
- Notify affected users if the domain appears malicious
- Review follow-on cloud and identity activity for clicked users

## Analyst Notes
This is a good early campaign signal rather than a definitive malicious verdict. It becomes much stronger when followed by identity abuse, phishing outcomes, or suspicious downloads.