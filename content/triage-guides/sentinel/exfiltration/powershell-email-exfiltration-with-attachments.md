# PowerShell Email Exfiltration with Attachments

## Goal
Identify PowerShell-based email activity that includes attachment handling and may indicate scripted exfiltration through SMTP or mail libraries.

## Why This Alert Matters
PowerShell can be used to send files out through email by calling SMTP libraries or built-in mail functions. Although some internal automation still uses this pattern, attackers can abuse it to exfiltrate documents, archives, or collected data without relying on cloud storage or direct outbound transfer tools. This guide is based on a detection that looks for PowerShell command lines referencing `Send-MailMessage`, `SmtpClient`, `-Attachments`, and SMTP-related terms. :contentReference[oaicite:27]{index=27}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- `FileName` is `powershell.exe` or `pwsh.exe`

and the command line contains:
- `Send-MailMessage`
- `SmtpClient`
- `-Attachments`
- `smtp` :contentReference[oaicite:28]{index=28}

## Likely ATT&CK Mapping
- **T1020** – Automated Exfiltration
- **T1048** – Exfiltration Over Alternative Protocol

## Initial Triage Questions
1. What recipients or domains were referenced?
2. What files or attachments were named in the command?
3. Was the script approved and expected on the host?
4. Did the activity follow document access, archive creation, or browser credential access?
5. Was the sender account a user, service account, or automation account?
6. Was the mail target internal or external?
7. Did the same script also stage or collect data before sending?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Review the PowerShell command
- Inspect whether the command references:
  - SMTP server
  - recipient addresses
  - attachment paths
  - subject/body automation
- Determine whether the script uses built-in mail functionality or a library.

### 2. Identify the attachments
- Extract any file paths or filenames from the command line.
- Determine whether the files include:
  - documents
  - spreadsheets
  - archives
  - browser data
  - logs
  - exports

### 3. Correlate with staging or collection
Look for:
- archive creation
- document access
- browser credential store access
- clipboard collection
- mass file access
- temp or AppData staging

### 4. Validate business context
- Determine whether the script belongs to:
  - alerting
  - internal notification
  - legacy admin automation
  - lab validation
- Check whether the script source, path, and signer match approved tooling.

### 5. Determine exfiltration direction
- Review whether recipients are:
  - internal-only
  - partner-managed
  - external personal addresses
  - suspicious or newly observed
- External recipient use significantly raises concern.

## Common Benign Explanations
- Approved scripted alerting or email notifications
- Legacy automation using `Send-MailMessage`
- Internal notification scripts with attachments :contentReference[oaicite:29]{index=29}

## Escalate When
Escalate if:
- the script sends attachments externally
- the attachment paths reference sensitive or staged files
- the host recently showed collection or archive creation activity
- the script source is unapproved or suspicious
- the same endpoint shows other exfiltration or credential-access behavior

## Suggested Response Actions
- Preserve the full PowerShell command line
- Collect the script if present
- Identify the mail server, recipients, and attachment paths
- Review whether the files were also uploaded or archived elsewhere
- Search for the same script or SMTP usage across the environment
- Contain the endpoint if malicious scripted exfiltration is confirmed

## Analyst Notes
This is a high-value exfiltration analytic because email-based data transfer can bypass assumptions about cloud uploads or direct file transfer. It is strongest when paired with archive creation or prior collection behavior.