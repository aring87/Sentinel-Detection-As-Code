# OAuth Redirection Abuse Followed by Suspicious Execution

## Goal
Identify suspicious OAuth authorization URL click activity followed closely by browser-driven download or suspicious endpoint execution.

## Why This Alert Matters
OAuth lure abuse can be used to move users through a trusted-seeming authentication flow while redirecting them toward attacker-controlled infrastructure or staged payload delivery. When suspicious OAuth-related clicks are followed by script interpreters, installers, or LOLBins on the endpoint, the activity may indicate phishing, malicious redirect handling, or staged execution after user interaction. This guide is based on a correlation rule that ties suspicious OAuth click telemetry to suspicious endpoint execution within a short time window for the same user. :contentReference[oaicite:16]{index=16}

## What the Detection Is Looking For
This detection correlates:
- `UrlClickEvents` involving suspicious OAuth authorization patterns
- `DeviceProcessEvents` involving suspicious execution shortly afterward

The click side looks for:
- OAuth or Microsoft login authorization flows
- `prompt=none`
- `redirect_uri=`
- clicked-through or allowed actions

The endpoint side looks for execution of:
- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `mshta.exe`
- `rundll32.exe`
- `wscript.exe`
- `cscript.exe`
- `msiexec.exe`

It also looks for execution command lines with:
- `http://`
- `https://`
- `download`
- `curl`
- `iwr`
- `irm`
- `/i` :contentReference[oaicite:17]{index=17}

## Likely ATT&CK Mapping
- **T1566.002** – Phishing: Spearphishing Link
- **T1204** – User Execution

## Initial Triage Questions
1. What OAuth link or redirect chain did the user click?
2. Was the click expected as part of a legitimate workflow?
3. How soon after the click did execution begin?
4. Which process executed on the endpoint?
5. Did the execution chain imply download, installer launch, or LOLBin abuse?
6. Was the redirect destination suspicious or unusual?
7. Did the same user also show mailbox access, app consent, or other phishing indicators?

## Key Fields To Review
- `ClickTime`
- `ExecTime`
- `JoinUser`
- `DeviceName`
- `Url`
- `UrlChain`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`

## Investigation Steps

### 1. Review the OAuth click chain
- Inspect the full clicked URL and redirect chain.
- Determine whether the chain includes:
  - Microsoft login endpoints
  - suspicious redirect parameters
  - attacker-controlled redirect targets
  - auto-download or staged-delivery behavior
- Confirm whether the user expected the authorization flow.

### 2. Review the execution that followed
- Identify which binary executed after the click.
- Determine whether the command line indicates:
  - download behavior
  - LOLBin execution
  - installer launch
  - script retrieval
  - staged payload execution

### 3. Assess timing and causality
- Confirm that the execution occurred close enough to the click to support likely linkage.
- Prioritize cases where execution begins soon after the click and where the executed binary is unusual for the host.

### 4. Check for broader phishing or cloud-abuse indicators
Look for:
- mailbox access
- OAuth consent abuse
- risky sign-ins
- device code sign-ins
- inbox rule creation
- suspicious browser downloads
- fake CAPTCHA or support-scam activity

### 5. Validate legitimate business context
- Determine whether the OAuth flow was:
  - approved application authorization testing
  - legitimate admin sign-in work
  - expected application onboarding
- If the user and device context do not support that explanation, escalate.

## Common Benign Explanations
- Legitimate admin download or installation workflows after OAuth testing
- Approved application authorization testing followed by normal software installation :contentReference[oaicite:18]{index=18}

## Escalate When
Escalate if:
- the redirect target is suspicious or attacker-controlled
- execution follows the click quickly and involves LOLBins or script interpreters
- the user did not expect the OAuth flow
- the same user also shows mailbox, consent, or risky sign-in abuse
- the endpoint command line indicates download, staging, or remote content retrieval

## Suggested Response Actions
- Preserve both click telemetry and endpoint execution evidence
- Review browser history, downloads, and relevant mail or collaboration context
- Revoke tokens or sessions if cloud abuse is suspected
- Isolate the endpoint if malicious execution is confirmed
- Search for the same lure or URL chain across other users
- Review related OAuth and cloud identity activity for the user

## Analyst Notes
This is a strong correlation analytic because it links suspicious user interaction with immediate endpoint execution. It is especially valuable when phishing is increasingly blended with cloud identity abuse and trusted-looking authentication flows.