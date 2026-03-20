# Malicious Copy and Paste PowerShell from Explorer

## Goal
Identify likely paste-and-run activity where a user is tricked into launching PowerShell, CMD, or a LOLBin from Explorer or the Run dialog with suspicious download, hidden, or obfuscated arguments.

## Why This Alert Matters
This behavior is commonly associated with social-engineering campaigns such as fake CAPTCHA, ClickFix, or “copy this to verify” lures. It often leads directly to malware download, remote access tooling, or credential theft.

## What the Detection Is Looking For
This detection looks for:
- `explorer.exe` launching:
  - `powershell.exe`
  - `pwsh.exe`
  - `cmd.exe`
  - `wscript.exe`
  - `cscript.exe`
  - `mshta.exe`
  - `rundll32.exe`
- command lines with indicators such as:
  - `-enc`
  - `downloadstring`
  - `iwr`
  - `curl`
  - `iex`
  - `frombase64string`
  - `javascript:`
  - hidden execution

## Initial Triage Questions
1. Did the user intentionally run the command?
2. Was the user interacting with a suspicious website, fake CAPTCHA, or tech-support prompt?
3. Did the command download or launch a second-stage payload?
4. Did browser activity or clipboard-related lures occur immediately beforehand?

## Key Evidence To Review
- full `ProcessCommandLine`
- parent process and child process chain
- browser history or URL click telemetry
- nearby file downloads, especially into temp or user-writable paths
- follow-on network connections or RMM launches

## Investigation Steps
1. Review the exact command line and decode or deobfuscate it if needed.
2. Check whether the command downloaded content or executed inline code.
3. Review recent browser activity and user prompts that may explain paste-and-run behavior.
4. Look for follow-on payloads such as PowerShell downloaders, RMM tools, or stealers.
5. Determine whether the user reports being tricked into “verifying” or “fixing” something.

## Common Benign Explanations
- Admin or developer manually running a command from Run
- Internal troubleshooting steps performed by IT
- Lab testing

## Escalate When
Escalate if:
- the command is obfuscated or downloads remote content
- the user denies knowing what they ran
- follow-on payloads, persistence, or exfiltration occur
- the behavior matches a phishing or fake-support lure

## Suggested Response Actions
- isolate the endpoint if second-stage execution is confirmed
- preserve the full command line and any downloaded files
- block related URLs or domains
- notify the user’s management and IR if compromise is likely

## Analyst Notes
This is a high-confidence execution alert when paired with browser lure activity or follow-on remote tooling.