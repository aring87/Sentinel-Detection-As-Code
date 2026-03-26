# Triage Guide: Suspicious Microsoft 365 Inbox Rule for Forwarding or Deletion

## What this detects
New or modified inbox rules that forward, redirect, hide, move, or delete mail.

## Why it matters
Attackers use these rules to suppress alerts, hide security emails, and maintain quiet access.

## Immediate questions
1. Did the mailbox owner create the rule?
2. Does the rule target security notifications or external forwarding?
3. Did the mailbox recently have suspicious sign-ins?
4. Are there related OAuth grants, mailbox permissions, or transport rule changes?

## Investigative steps
- Review the full Parameters field and targeted destinations.
- Check recent sign-ins and impossible travel for the affected user.
- Inspect mailbox delegation, app consent, and MFA posture.
- Search for other inbox rules created by the same source IP or actor.
- Disable the rule and preserve evidence if malicious.

## Escalation indicators
- External forwarding target
- Delete or move-to-folder actions for alert mail
- Rule created right after suspicious authentication
- Multiple stealth-oriented mailbox changes

## Likely false positives
- Legitimate mailbox automation
- Executive assistant or support workflow rules
