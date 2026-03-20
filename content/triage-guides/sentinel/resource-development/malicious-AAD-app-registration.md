# Malicious AAD App Registration

## Goal
Identify Azure AD application registration events that may indicate malicious cloud resource setup.

## Why This Alert Matters
Application registration is a meaningful cloud control-plane event, but this older rule is much narrower than the standardized version.

## What the Detection Is Looking For
This detection only checks `AuditLogs` for:
- `OperationName has 'Add application'` :contentReference[oaicite:15]{index=15}

## Investigation Steps
- validate whether the add-application event is legitimate
- compare to the broader standardized app-registration guide
- determine whether this rule should be retained only for backward compatibility

## Analyst Notes
Treat this as a legacy or supplemental guide. Prefer the standardized suspicious Azure AD application registration guide as the primary triage path.