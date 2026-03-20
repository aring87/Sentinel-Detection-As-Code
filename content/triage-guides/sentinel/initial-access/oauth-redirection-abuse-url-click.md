# OAuth Redirection Abuse URL Click

## Goal
Identify phishing clicks involving suspicious Microsoft OAuth authorization links that may redirect users into attacker-controlled workflows.

## Why This Alert Matters
OAuth authorization links can appear legitimate to users because they reference trusted Microsoft domains. Attackers abuse redirection parameters and prompt handling to deliver phishing, auth abuse, or malware.

## What the Detection Is Looking For
This detection looks for:
- URL clicks involving Microsoft OAuth authorize paths
- suspicious parameters such as:
  - redirect URI manipulation
  - prompt suppression
  - unusual scope behavior

## Initial Triage Questions
1. What message or lure caused the click?
2. Did the link redirect to a non-Microsoft destination?
3. Was the user prompted to sign in, authorize, or download something?
4. Did the click lead to risky sign-ins or endpoint activity?

## Key Evidence To Review
- full clicked URL
- full URL chain
- email subject and sender
- recipient user
- redirect target
- nearby sign-ins or browser downloads

## Investigation Steps
1. Review the clicked URL and its parameters.
2. Trace the full redirect path to see where the user landed.
3. Determine whether the email used a lure such as e-signature, secure message, voicemail, or collaboration invite.
4. Check for device code sign-ins, risky logins, or follow-on endpoint execution.
5. Determine whether the same URL was clicked by multiple users.

## Common Benign Explanations
- rare developer testing
- internal OAuth troubleshooting
- benign application login workflows

## Escalate When
Escalate if:
- the redirect target is suspicious
- the user entered credentials or approved access
- endpoint execution followed the click
- multiple users were targeted

## Suggested Response Actions
- block the URL/domain if malicious
- identify all recipients and clickers
- review sign-ins and endpoint activity for impacted users
- notify email security and IR teams

## Analyst Notes
This is primarily a delivery-stage alert and should be correlated with identity and endpoint activity.