# OAuth Redirection Abuse Followed by Browser Download

## Goal
Identify suspicious OAuth phishing links that are followed by browser-driven download or payload execution.

## Why This Alert Matters
This pattern suggests the user clicked a Microsoft-branded auth link and was then redirected into malware delivery or scripted execution. It bridges phishing into endpoint compromise.

## What the Detection Is Looking For
This detection looks for:
- suspicious OAuth authorization URL click activity
- followed by browser-related download or execution
- using installers or LOLBins

## Initial Triage Questions
1. What file or payload was downloaded?
2. Was the user redirected to an attacker-controlled site?
3. Did the payload launch through a browser, installer, or script host?
4. Did the user report seeing a fake Microsoft auth page?

## Key Evidence To Review
- clicked URL and redirect chain
- endpoint process creation
- browser download history
- downloaded file names and hashes
- process ancestry and execution timing

## Investigation Steps
1. Review the clicked OAuth link and determine final destination.
2. Identify what was downloaded or launched.
3. Check whether the payload executed via PowerShell, CMD, MSHTA, MSIExec, or Rundll32.
4. Determine whether the user was prompted to approve anything or just click through.
5. Review for persistence, RMM, credential theft, or exfiltration after execution.

## Common Benign Explanations
- legitimate software downloads after SSO-based login
- testing by developers or IT
- approved installers launched after portal sign-in

## Escalate When
Escalate if:
- the redirect target is malicious or suspicious
- payload execution follows quickly
- obfuscated or download-heavy command lines appear
- additional malicious behaviors are detected

## Suggested Response Actions
- isolate the endpoint if execution occurred
- collect the downloaded file and command line evidence
- review all other recipients of the same message
- block related URLs and payload indicators

## Analyst Notes
This is a strong cross-domain detection because it correlates mail/browser activity with endpoint execution.