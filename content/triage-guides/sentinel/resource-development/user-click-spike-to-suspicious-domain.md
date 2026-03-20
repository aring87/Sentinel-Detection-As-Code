# User Click Spike to Suspicious Domain

## Goal
Identify repeated user clicks to the same external domain that may indicate attacker-controlled phishing infrastructure or a coordinated malicious campaign.

## Why This Alert Matters
When multiple users click the same destination in a short time period, it can indicate an active phishing campaign, credential-harvesting site, or attacker-hosted infrastructure. The behavior is especially concerning when the domain is newly observed, uncommon, or followed by suspicious sign-ins. :contentReference[oaicite:11]{index=11}

## What the Detection Is Looking For
This detection reviews `UrlClickEvents` where:
- `ActionType =~ "ClickAllowed"`
- the domain is extracted from the URL
- clicks are summarized by domain in 1-day buckets

It alerts when:
- clicks are at least 5
- distinct users are at least 3 :contentReference[oaicite:12]{index=12}

## Likely ATT&CK Mapping
- T1583.001 – Acquire Infrastructure: Domains
- Also relevant to Initial Access when tied to phishing delivery. :contentReference[oaicite:13]{index=13}

## Initial Triage Questions
1. What domain was clicked?
2. Is the domain newly observed, suspicious, or impersonating a trusted service?
3. Which users clicked it, and did they come from the same email campaign?
4. Did any clicked users later show suspicious authentication or mailbox activity?
5. Is the domain tied to a known marketing or internal communications campaign instead?

## Key Fields To Review
- Domain
- Timestamp
- Clicks
- Users

## Investigation Steps
### 1. Validate the spike
- Confirm the click count and distinct user count.
- Determine whether clicks happened in a tight cluster or across the day.
- Identify whether one or multiple campaigns drove the activity.

### 2. Review the domain
- Assess whether the domain is:
  - newly observed
  - typo-squatted
  - impersonating a brand
  - unrelated to the users’ business function
- Check related email messages or campaigns that referenced the domain.

### 3. Identify impacted users
- Determine which users clicked and whether they are high-value or privileged.
- Review whether the same users later showed:
  - suspicious sign-ins
  - device-code authentication
  - mailbox rule changes
  - credential-harvesting symptoms

### 4. Correlate with email and identity telemetry
Check for:
- suspicious inbound messages
- attachment or link phishing alerts
- device-code phishing
- risky sign-ins or impossible travel
- app registration or consent abuse

### 5. Assess business legitimacy
- Determine whether the domain belongs to a legitimate marketing, training, or internal campaign.
- Validate with communications or email-security teams where needed.

## Common Benign Explanations
- Marketing campaigns
- Internal awareness or training campaigns
- Legitimate external services accessed by many users :contentReference[oaicite:14]{index=14}

## Escalate When
Escalate if:
- the domain is suspicious, newly seen, or impersonating a trusted service
- multiple users clicked from the same phishing campaign
- clicked users later show auth or mailbox abuse
- the domain is connected to credential harvesting or malware delivery

## Suggested Response Actions
- preserve the domain, campaign, and impacted-user list
- search for all related email messages and URLs
- warn or notify impacted users
- block the domain or associated indicators if malicious
- review follow-on identity activity for all clickers

## Analyst Notes
This is a strong bridge guide between Resource Development and Initial Access. Keep it in resource-development if you want to track attacker infrastructure and campaign buildup, but it also maps naturally to phishing response workflows.