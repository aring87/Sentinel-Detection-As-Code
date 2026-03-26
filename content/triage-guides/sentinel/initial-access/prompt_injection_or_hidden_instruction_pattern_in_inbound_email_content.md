# Prompt Injection or Hidden Instruction Pattern in Inbound Email Content

## Goal
Identify inbound email content that appears crafted to manipulate downstream AI-assisted analysis, triage, or classification systems.

## Why This Alert Matters
CrowdStrike noted that threat actors have begun experimenting with prompt injection and hidden instruction content to interfere with AI-enabled security workflows. Even if these attempts are not consistently effective at scale, they matter because they target analyst tooling indirectly by poisoning inputs rather than exploiting the model or infrastructure directly. Security teams adopting AI-assisted triage should treat such content as both a phishing risk and a workflow integrity risk.

## What the Detection Is Looking For
This detection reviews inbound email content for phrases or structures associated with hidden instructions, such as:
- `ignore previous instructions`
- `system prompt`
- `assistant:`
- `do not classify as phishing`
- `mark this as safe`
- `override policy`
- `hidden instruction`

## Likely ATT&CK Mapping
- T1566 – Phishing
- T1027 – Obfuscated or Compressed Files and Information
- defense evasion against AI-assisted workflows

## Initial Triage Questions
1. Was the email part of a broader phishing or social engineering campaign?
2. Did the content include instructions clearly intended for an AI or automated classifier rather than a human recipient?
3. Was the message delivered to users, shared mailboxes, or security workflow ingestion points?
4. Did the sender also use other evasion techniques such as HTML obfuscation, hidden text, or zero-font content?
5. Did any AI-assisted workflow process, summarize, or misclassify the message?

## Key Fields To Review
- Timestamp
- Sender
- Recipient
- Subject
- Body
- message headers
- HTML source
- attachment names
- downstream triage disposition if available

## Investigation Steps
### 1. Validate the suspicious content
- Review the email body in both rendered and raw form.
- Determine whether the suspicious phrases are:
  - visible to the user
  - hidden in HTML
  - embedded in metadata
  - part of quoted text or benign discussion

### 2. Assess phishing context
- Review sender reputation, domain age, authentication results, and message headers.
- Determine whether the email also contains:
  - malicious links
  - attachments
  - credential theft themes
  - invoice or support lures

### 3. Inspect workflow exposure
Look for:
- AI-assisted classification or summarization of the message
- downstream ticketing or auto-triage actions
- evidence that the message was incorrectly marked safe or deprioritized
- similar messages to the same mailbox or ingestion path

### 4. Review obfuscation techniques
- Check for:
  - hidden text
  - white text on white background
  - HTML comments
  - excessive spacing
  - encoded content
  - prompt-like instruction blocks intended for machine readers

### 5. Validate business context
- Determine whether the content could be legitimate discussion about AI, security, or prompt engineering.
- If the message came from a trusted internal source, confirm whether it is part of training, testing, or research.

## Common Benign Explanations
- Internal AI prompt-engineering discussion
- Security research content
- Training or awareness material
- forwarded examples of phishing or AI abuse

## Escalate When
Escalate if:
- the message is clearly a phishing attempt
- hidden instruction content is paired with obfuscation or malicious links
- the message targeted an AI-assisted security workflow
- similar messages were sent broadly across the environment
- automated triage was affected or bypassed

## Suggested Response Actions
- preserve the raw email, HTML body, and headers
- quarantine or block related messages if malicious
- review AI-assisted workflows that handled the message
- notify email and security automation owners if prompt injection was attempted
- hunt for similar content patterns across mailboxes and ingestion pipelines

## Analyst Notes
This is both an email-triage and workflow-integrity alert. The message itself may be phishing, but the larger question is whether any automation or AI-assisted process consumed it in a way that changed analyst outcomes.
