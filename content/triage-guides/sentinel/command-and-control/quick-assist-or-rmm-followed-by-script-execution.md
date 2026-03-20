# Quick Assist or RMM Followed by Script Execution

## Goal
Identify suspicious remote support or RMM sessions that are quickly followed by script execution or command-and-control setup.

## Why This Alert Matters
Adversaries increasingly use Quick Assist and commercial RMM tools to gain interactive access after social engineering. The real signal is not just the RMM tool itself, but the immediate scripting or payload activity that follows.

## What the Detection Is Looking For
This detection looks for:
- RMM/remote-support tools such as:
  - `quickassist.exe`
  - `anydesk.exe`
  - `teamviewer.exe`
  - `screenconnect`
  - `simplehelp`
  - `netsupportmanager`
- followed within 30 minutes by suspicious script execution from:
  - PowerShell
  - CMD
  - WSH
  - MSHTA
  - Rundll32

## Initial Triage Questions
1. Was the remote session approved or expected?
2. Did the user request support?
3. What script or command executed after the session started?
4. Did persistence, credential theft, or exfiltration follow?

## Key Evidence To Review
- RMM process start time
- script execution time and command line
- user helpdesk tickets or support records
- network connections, file downloads, and persistence events
- account context for the remote session

## Investigation Steps
1. Confirm whether the RMM tool is approved in your environment.
2. Determine whether the user was socially engineered into accepting remote help.
3. Review what was executed after the session began.
4. Check for downloaded tools, persistence, credential dumping, or cloud login abuse.
5. Determine whether the session originated from a sanctioned admin workflow or an attacker.

## Common Benign Explanations
- Helpdesk support
- approved remote administration
- software vendor troubleshooting

## Escalate When
Escalate if:
- the user did not request help
- scripting begins shortly after session establishment
- suspicious tools or persistence are dropped
- multiple systems show the same remote-support pattern

## Suggested Response Actions
- terminate active remote sessions
- isolate the host if malicious activity is ongoing
- reset credentials if account compromise is suspected
- review other users targeted by the same lure or operator

## Analyst Notes
This alert is strongest when the RMM tool is uncommon for the host or user and scripting begins immediately afterward.