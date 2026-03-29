# Suspicious Microsoft 365 Inbox Rule for Forwarding or Deletion

## Goal
Identify creation or modification of inbox rules that forward, redirect, delete, or hide emails in Microsoft 365.

## Why This Alert Matters
Inbox rules are a classic mailbox-persistence technique. Attackers use them to auto-forward sensitive mail, silently delete alerts, hide messages in folders, or mark items as read so the victim misses evidence of compromise. This guide is based on a rule that reviews `OfficeActivity` for `New-InboxRule` and `Set-InboxRule` events with forwarding, redirect, delete, or concealment-related parameters. :contentReference[oaicite:14]{index=14}

## What the Detection Is Looking For
This detection reviews `OfficeActivity` for:
- `New-InboxRule`
- `Set-InboxRule`

It looks for parameters such as:
- `ForwardTo`
- `RedirectTo`
- `DeleteMessage`
- `MoveToFolder`
- `MarkAsRead`
- `StopProcessingRules`

It surfaces the user, client IP, rule operation, workload, parameters, and result status. :contentReference[oaicite:15]{index=15}

## Likely ATT&CK Mapping
- **T1114.003** – Email Collection: Email Forwarding Rule
- **T1564** – Hide Artifacts

## Initial Triage Questions
1. What inbox rule was created or modified?
2. Did it forward to an external address or redirect sensitive mail?
3. Was the mailbox owner aware of or responsible for the change?
4. Did the rule delete, move, or mark messages as read?
5. Was the mailbox recently accessed from a risky or unusual sign-in?
6. Are there related app-consent, delegation, or Graph-access indicators?
7. Did the rule target security, finance, or executive communications?

## Key Fields To Review
- `TimeGenerated`
- `UserId`
- `Operation`
- `OfficeWorkload`
- `ClientIP`
- `Parameters`
- `ResultStatus`

## Investigation Steps

### 1. Review the rule action
- Determine whether the rule:
  - forwards mail externally
  - redirects mail
  - deletes or hides messages
  - moves mail to a specific folder
  - marks mail as read
- Identify whether the rule is clearly intended to conceal activity.

### 2. Identify impacted messages
- Review whether the rule targeted:
  - all mail
  - specific senders
  - security alerts
  - finance or HR topics
  - executive communications
- Hidden or deleted security-related mail is especially suspicious.

### 3. Validate mailbox ownership and sign-in context
- Confirm whether the mailbox owner created or approved the rule.
- Review recent sign-ins for:
  - unusual IPs
  - risky sign-ins
  - device-code activity
  - impossible travel or suspicious locations

### 4. Correlate with related cloud activity
Look for:
- mailbox access spikes
- Graph mail access
- OAuth abuse
- delegation changes
- external sharing
- OneDrive/SharePoint downloads
- additional inbox-rule modifications

### 5. Validate benign workflow context
- Some rules are created for:
  - assistant routing
  - ticketing workflows
  - legitimate organization or support processes
- These should still be verifiable with the mailbox owner or admins.

## Common Benign Explanations
- User-created mailbox organization rules
- Admin-created support or workflow rules
- Approved assistant or routing automations :contentReference[oaicite:16]{index=16}

## Escalate When
Escalate if:
- the rule forwards externally
- the rule hides, deletes, or marks messages read without clear approval
- the mailbox owner denies creating the rule
- there are risky sign-ins or other cloud-abuse indicators nearby
- the rule targets security or finance-related messages

## Suggested Response Actions
- Preserve the mailbox audit event and rule parameters
- Review the rule directly in the mailbox
- Remove or disable the rule if unauthorized
- Review recent mailbox access and sign-in history
- Search for similar rule creation across other users
- Revoke sessions or reset credentials if account compromise is suspected

## Analyst Notes
This is a high-value mailbox-persistence detection. Even a single suspicious inbox rule can indicate active compromise, ongoing collection, or concealment of attacker activity.