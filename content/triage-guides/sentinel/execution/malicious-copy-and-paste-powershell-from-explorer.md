# Paste-and-Run Shell or Script Execution from Explorer

## Goal
Identify likely copy-paste execution behavior launched from Explorer or shell context into PowerShell, CMD, or other script interpreters.

## Why This Alert Matters
A common social-engineering pattern is to trick the user into copying and pasting a malicious command into Run, CMD, or PowerShell. This can happen through fake support, fake CAPTCHA, “verification” prompts, or malicious setup instructions. Because the command is user-initiated and often launched from Explorer shell context, it can bypass some expectations of traditional malware delivery. This guide is based on a detection that looks for Explorer-launched script or shell execution with download, encoded-command, or remote-execution indicators. :contentReference[oaicite:10]{index=10}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` where:
- `InitiatingProcessFileName` is `explorer.exe`

and the child process is one of:
- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`
- `rundll32.exe`

It then looks for suspicious command-line content such as:
- `http://`
- `https://`
- `-enc`
- `-encodedcommand`
- `frombase64string`
- `invoke-expression`
- `iwr`
- `irm`
- `curl`
- `wget`
- `javascript:`
- `cmd /c`
- `powershell -` :contentReference[oaicite:11]{index=11}

## Likely ATT&CK Mapping
- **T1059** – Command and Scripting Interpreter
- **T1204.001** – User Execution: Malicious Link

## Initial Triage Questions
1. Did the user paste a command into Run, CMD, or PowerShell?
2. Which interpreter was launched from Explorer?
3. Does the command line include download, decode, or execution behavior?
4. Did the user recently interact with a suspicious webpage, email, or external support contact?
5. Was the process launched from a normal shell action or a deceptive workflow?
6. Did this occur alongside Quick Assist, fake CAPTCHA, or browser-lure activity?
7. Was there follow-on persistence, staging, or credential access?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `FileName`
- `ProcessCommandLine`
- `SHA1`
- `SHA256`
- `ReportId`

## Investigation Steps

### 1. Confirm interactive shell context
- Validate that Explorer was the parent process.
- Determine whether the launch likely came from:
  - Run dialog
  - double-click or shell action
  - command pasted into an interactive shell
- Review nearby user-driven events such as browser activity or file downloads.

### 2. Inspect the command
- Review the full child-process command line.
- Determine whether it contains:
  - remote URLs
  - encoded payloads
  - download cradles
  - inline script execution
  - chained shell commands
- Decode or deobfuscate as needed.

### 3. Validate user narrative
- Ask whether the user was instructed to paste the command.
- Check for:
  - fake CAPTCHA prompts
  - support scams
  - Quick Assist requests
  - email or chat lure messages
- This is often the strongest context signal.

### 4. Check for follow-on activity
Look for:
- browser-to-script execution
- suspicious web downloads
- PowerShell external network traffic
- scheduled task or Run key persistence
- browser credential access
- archive creation and exfiltration

### 5. Determine whether the command executed successfully
- Search for child processes, file writes, and network activity after the command.
- Review whether payloads were staged or executed from writable paths.

## Common Benign Explanations
- Administrator troubleshooting from Explorer shell context
- Developer testing of shell commands
- Approved internal tools launched interactively by users :contentReference[oaicite:12]{index=12}

## Escalate When
Escalate if:
- the user confirms they were tricked into pasting a command
- the command downloads or decodes a payload
- the process launches from Explorer and quickly reaches network, persistence, or credential-access activity
- the same device shows fake CAPTCHA or remote-support scam indicators
- the command is clearly malicious or obfuscated

## Suggested Response Actions
- Preserve the full process tree and command line
- Identify the original lure source if possible
- Collect related browser, email, or chat evidence
- Isolate the endpoint if follow-on malicious activity is confirmed
- Search for the same command pattern on other hosts
- Educate the user if this was social-engineering driven

## Analyst Notes
This is a strong user-execution analytic because it captures the increasingly common “paste this command” attack pattern. It is especially high value when tied to support scams, fake CAPTCHA pages, or browser-delivered lures.