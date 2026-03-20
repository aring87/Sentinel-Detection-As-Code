# SharePoint or SaaS Third-Party Integration Secret Access

## Goal
Identify suspicious access or modification activity involving integration credentials, application secrets, or config files related to third-party SaaS connections.

## Why This Alert Matters
Third-party integration credentials are attractive supply-chain targets. Access to integration config, secrets, or related application credentials can enable downstream cloud or SaaS abuse.

## What the Detection Is Looking For
This detection looks for:
- app/service principal credential changes
- file access to objects with names suggesting:
  - secrets
  - credentials
  - integration config
  - tokens
  - app settings

## Initial Triage Questions
1. Was the user expected to maintain integrations?
2. What secret or config object was accessed?
3. Did app credential changes occur around the same time?
4. Did follow-on API or cloud access occur?

## Key Evidence To Review
- secret/config file names and paths
- affected SaaS or SharePoint site
- initiator identity
- app credential changes
- API usage after access

## Investigation Steps
1. Determine whether the accessed object truly contains credentials or integration settings.
2. Validate whether the actor normally performs integration maintenance.
3. Review concurrent app registration, credential rotation, or service principal changes.
4. Check for follow-on API use, data export, or mailbox/file access.
5. Assess whether this aligns with approved maintenance or malicious reconnaissance.

## Common Benign Explanations
- approved secret rotation
- integration maintenance
- legitimate application updates

## Escalate When
Escalate if:
- the actor is not expected to access integration secrets
- secret/config access overlaps with app credential changes
- follow-on abuse of the connected SaaS or API occurs
- multiple secret-bearing objects were accessed unexpectedly

## Suggested Response Actions
- rotate affected credentials or secrets
- review related app/service-principal activity
- investigate downstream access using those credentials
- notify application owners and cloud/security teams

## Analyst Notes
This works best in environments with mature SharePoint and SaaS audit coverage.