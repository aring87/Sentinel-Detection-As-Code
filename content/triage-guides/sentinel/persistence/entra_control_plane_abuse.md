# Triage Guide: Suspicious Entra ID Control-Plane Changes by Nonstandard Actor

## What this detects
High-risk Entra changes such as conditional access updates, MFA method registration, service principal credential changes, or app privilege changes.

## Why it matters
These changes can establish persistence, bypass controls, and extend access across hybrid identity.

## Immediate questions
1. Is the actor a normal IAM administrator?
2. What exact object was modified?
3. Did the same actor recently sign in from a new IP, device, or geography?
4. Were there related mailbox, OAuth, or federated identity changes?

## Investigative steps
- Review AuditLogs and SigninLogs for the actor before and after the change.
- Inspect AdditionalDetails and TargetResources contents.
- Compare the change against approved CAB or admin change windows.
- Check for suspicious device registrations, MFA additions, and app secrets.
- Review parallel activity in Exchange Online, SharePoint, and Defender portals.

## Escalation indicators
- Actor is not a normal identity admin
- New credential or federated identity added
- Conditional access weakened or bypass-oriented
- Same actor also modified email or EDR policies

## Likely false positives
- Planned IAM administration
- Tenant hardening or application onboarding
