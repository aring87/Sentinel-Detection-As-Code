# Suspicious OAuth Consent Grant with High-Risk Permissions

## Goal
Identify application consent grants that may enable mailbox access, file access, or token abuse through malicious or unauthorized OAuth apps.

## Why This Alert Matters
Consent phishing and application access token abuse allow attackers to access data without repeatedly authenticating as the user. High-risk permissions can expose mail, files, directories, and offline access.

## What the Detection Is Looking For
This detection looks for:
- consent or delegated permission grant events
- permissions such as:
  - `Mail.Read`
  - `Mail.ReadWrite`
  - `Mail.Send`
  - `Files.Read.All`
  - `Files.ReadWrite.All`
  - `offline_access`
  - `Directory.Read.All`

## Initial Triage Questions
1. Was the app approved by IT or identity administrators?
2. Who granted consent?
3. What permissions were requested?
4. Did the app later access mailbox or file content?

## Key Evidence To Review
- application name and publisher
- granted permissions
- consent initiator
- service principal or app sign-in history
- follow-on mailbox, SharePoint, or file access

## Investigation Steps
1. Validate whether the app is known and approved.
2. Review the exact permissions granted and why they were needed.
3. Check for suspicious user prompts, phishing emails, or device-code abuse around the same time.
4. Review service principal sign-ins and API calls after consent.
5. Determine whether the app appears attacker-controlled or abused.

## Common Benign Explanations
- approved enterprise integrations
- sanctioned SaaS onboarding
- admin-approved application testing

## Escalate When
Escalate if:
- the app is unknown or suspicious
- permissions are overly broad
- the grant was initiated by a non-admin unexpectedly
- follow-on mailbox or file access occurs

## Suggested Response Actions
- revoke the consent grant
- disable or remove the service principal if malicious
- review affected users and their mailbox/file activity
- reset credentials or revoke sessions if related phishing occurred

## Analyst Notes
This is one of the highest-priority cloud identity alerts when broad permissions and unknown apps are involved.