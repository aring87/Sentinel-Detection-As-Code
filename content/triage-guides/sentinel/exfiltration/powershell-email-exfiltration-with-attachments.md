# PowerShell Email Exfiltration with Attachments

## Goal
Identify suspicious PowerShell-based email activity where scripts reference SMTP functionality and file attachments, which may indicate automated data exfiltration.

## Why This Alert Matters
PowerShell can be used to send email directly through SMTP libraries or built-in cmdlets. Attackers may script outbound email with attachments to move data outside the environment without relying on interactive user actions.

## What the Detection Is Looking For
This detection looks for PowerShell command lines containing indicators such as:
- `Send-MailMessage`
- `SmtpClient`
- `-Attachments`
- `smtp`

## Likely ATT&CK Mapping
- T1020 – Automated Exfiltration
- T1048 – Exfiltration Over Alternative Protocol

## Initial Triage Questions
1. What script or command launched the email activity?
2. Were attachments referenced in the command?
3. Who were the recipients?
4. Is the script approved automation or an unexpected ad hoc action?
5. Was there prior staging, archive creation, or file collection on the host?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- ProcessCommandLine
- InitiatingProcessFileName

## Investigation Steps
### 1. Validate the PowerShell execution
- Confirm whether `powershell.exe` or `pwsh.exe` launched the command.
- Review the full command line for:
  - SMTP server references
  - attachment paths
  - recipient addresses
  - subject/body text
  - encoded or obfuscated content

### 2. Determine script origin
- Identify whether the command came from:
  - a `.ps1` file
  - interactive shell execution
  - scheduled task
  - service account automation
  - a parent process such as Office, HTA, WMI, or another script host
- Check script path reputation and whether it lives in temp, user-writable, or admin-managed directories.

### 3. Review attachment targets
- Identify files referenced with `-Attachments` or equivalent patterns.
- Determine whether the files are:
  - archives
  - documents
  - exports
  - credential material
  - screenshots
  - logs or bulk user data

### 4. Review email destination context
- Determine whether recipients are:
  - internal
  - external personal email
  - unknown third-party addresses
  - shared mailboxes
- Review whether the SMTP server is sanctioned and expected.

### 5. Correlate with surrounding behavior
Look for preceding activity such as:
- archive creation
- clipboard collection
- screen capture
- file discovery or collection
- browser credential access
- temporary file staging

## Common Benign Explanations
- Legacy approved automation using `Send-MailMessage`
- Monitoring or alert scripts
- Admin scripts sending log bundles
- Test or lab automation

## Escalate When
Escalate if:
- attachments contain sensitive data
- recipients are unapproved external addresses
- the script came from a suspicious location
- the user or admin cannot explain the script
- the command is encoded, obfuscated, or launched by another suspicious process

## Suggested Response Actions
- capture the full PowerShell command line and process tree
- identify and preserve referenced attachments
- review mailbox or SMTP logs if available
- disable or contain the affected account if active exfiltration is suspected
- isolate the host if correlated malicious activity exists

## Analyst Notes
This guide should be your primary standardized email-exfil triage guide. If you want only one canonical version, prefer this one over the older broader email-exfil rule.