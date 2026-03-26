# Triage Guide: Suspicious Fake CAPTCHA Browser-to-Script Execution Chain

## What this detects
Browser-spawned PowerShell, CMD, mshta, rundll32, or similar interpreter activity with suspicious download or script execution strings.

## Why it matters
This aligns with fake CAPTCHA lures and browser-driven user execution patterns.

## Immediate questions
1. Which browser launched the child process?
2. Was the user just browsing a suspicious site or prompted to copy/paste commands?
3. Did the child process reach out to external URLs or download payloads?
4. Is there follow-on persistence, credential theft, or LOLBin use?

## Investigative steps
- Review full parent and child command lines.
- Check DeviceNetworkEvents for outbound connections from the child process.
- Review nearby DeviceFileEvents for payload writes.
- Check for subsequent PowerShell, scheduled tasks, Run keys, or service creation.
- Pull browser history, downloads, and SmartScreen or web filtering verdicts if available.

## Escalation indicators
- Encoded PowerShell or Invoke-Expression
- External payload download
- Child process chain into additional LOLBins
- Persistence or credential access shortly after execution

## Likely false positives
- Internal admin portal launching helper tools
- Developer or admin local script testing
