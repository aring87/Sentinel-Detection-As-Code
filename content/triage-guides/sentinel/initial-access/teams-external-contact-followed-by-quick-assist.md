# Teams External Contact Followed by Quick Assist

## Goal
Identify potential social-engineering chains where external Teams contact activity is followed by Quick Assist usage for the same user.

## Why This Alert Matters
Attackers increasingly use collaboration platforms and social engineering to contact users directly, build trust, and then convince them to launch remote-assistance tools. When external or guest Teams activity is followed shortly by Quick Assist on the same user’s device, that may indicate a help-desk scam, fake support interaction, or other social-engineering-driven initial access. This guide is based on a rule that correlates external Teams interaction with Quick Assist usage within a short time window. :contentReference[oaicite:21]{index=21}

## What the Detection Is Looking For
This detection correlates:
- `OfficeActivity` for Microsoft Teams events involving:
  - external
  - guest
  - federated parameters
- `DeviceProcessEvents` for:
  - `quickassist.exe`

It looks for Quick Assist activity occurring within roughly two hours of external or guest Teams interaction by the same user. :contentReference[oaicite:22]{index=22}

## Likely ATT&CK Mapping
- **T1566** – Phishing
- **T1219** – Remote Access Software

## Initial Triage Questions
1. Did the user recently interact with an external or guest Teams contact?
2. What was the nature of the Teams interaction: message, chat, call, or meeting?
3. Did Quick Assist start shortly afterward?
4. Was the user expecting support or remote help?
5. Did the external contact claim to be IT, support, or security staff?
6. Was there follow-on script execution, download, or file transfer after Quick Assist?
7. Does the sequence match any known scam or support-fraud pattern?

## Key Fields To Review
- `TeamsTime`
- `QATime`
- `UserUpn`
- `DeviceName`
- `Operation`
- `Parameters`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`

## Investigation Steps

### 1. Review the Teams interaction
- Determine whether the activity involved:
  - external message
  - guest chat
  - call
  - meeting participant addition
- Inspect parameters for evidence that the contact was external, federated, or guest.

### 2. Validate user expectation
- Confirm whether the user expected support or a remote-help request.
- Ask whether the contact claimed to be:
  - helpdesk
  - IT admin
  - security
  - vendor support
- Unexpected support narratives are highly relevant.

### 3. Review Quick Assist timing and use
- Confirm how quickly Quick Assist started after the Teams event.
- Review whether the session was:
  - user-initiated
  - expected
  - approved by IT
  - suspiciously timed with the external interaction

### 4. Check for follow-on malicious activity
Look for:
- script execution
- RMM tool launch
- suspicious downloads
- persistence creation
- file transfer or exfiltration
- archive creation
- browser credential access

### 5. Validate benign collaboration context
- Determine whether the Teams interaction was part of:
  - known external collaboration
  - approved support
  - guest meeting activity
- If the user and support records do not support the sequence, escalate.

## Common Benign Explanations
- Legitimate external Teams collaboration followed by support activity
- Guest meetings or chats that precede approved helpdesk sessions :contentReference[oaicite:23]{index=23}

## Escalate When
Escalate if:
- the user did not expect the Quick Assist session
- the external contact claimed to be IT or support without validation
- Quick Assist was followed by script execution, downloads, or data transfer
- the sequence aligns with help-desk scam or vishing patterns
- the same device shows persistence or credential-access behavior afterward

## Suggested Response Actions
- Preserve Teams, process, and timing evidence
- Validate the interaction directly with the user if appropriate
- Review Quick Assist session context and any support records
- Investigate follow-on endpoint behavior immediately
- Search for similar external Teams-to-Quick Assist sequences across other users
- Contain the device if remote-access abuse is confirmed

## Analyst Notes
This is a strong social-engineering sequence analytic. It is especially valuable in environments where collaboration tools are used heavily and attackers may exploit user trust rather than deliver traditional malware first.