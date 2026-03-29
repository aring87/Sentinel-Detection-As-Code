# Suspicious Browser Credential Store Access

## Goal
Identify non-browser processes accessing browser credential or session storage files that may be targeted for credential theft.

## Why This Alert Matters
Browser credential stores often contain saved passwords, session cookies, autofill data, and other sensitive artifacts. Attackers and infostealers frequently target these files because they can provide direct access to user accounts without needing traditional password capture methods.

When a non-browser process accesses these files, that may indicate credential theft, session hijacking preparation, or collection prior to exfiltration.

## What the Detection Is Looking For
This detection reviews `DeviceFileEvents` for file access in browser profile locations such as:
- Chrome user data
- Edge user data
- Firefox profiles

It specifically looks for access to files such as:
- `Login Data`
- `Cookies`
- `Web Data`
- `logins.json`
- `key4.db`

It excludes normal browser processes like:
- `chrome.exe`
- `msedge.exe`
- `firefox.exe`
- `brave.exe`

## Likely ATT&CK Mapping
- **T1555.003** – Credentials from Web Browsers

## Initial Triage Questions
1. Which process accessed the browser credential store?
2. Is that process approved, signed, and expected on the host?
3. Did the process run from a user-writable or suspicious path?
4. Which browser artifacts were accessed: passwords, cookies, or profile databases?
5. Was the activity followed by archiving, outbound traffic, or exfiltration?
6. Is the host used for forensics, browser repair, backup, or enterprise management?
7. Are there related infostealer or script-execution indicators on the system?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `InitiatingProcessAccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `FolderPath`
- `FileName`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Identify the accessing process
- Review the exact process name and command line.
- Determine whether the process is:
  - known good
  - signed
  - recently dropped
  - executing from a writable location
- Pay close attention to script hosts, archive tools, PowerShell, and unknown binaries.

### 2. Identify what browser data was touched
- Determine whether the process accessed:
  - saved credentials
  - cookies
  - profile databases
  - encryption key material
- Access to multiple browser artifact types may increase suspicion.

### 3. Look for follow-on collection or exfiltration
Check for:
- archive creation
- clipboard access
- PowerShell or LOLBin network activity
- suspicious cloud upload
- email exfiltration
- outbound traffic shortly after the file access

### 4. Validate legitimate tool usage
- Confirm whether the device is used for:
  - browser repair
  - migration
  - endpoint backup
  - enterprise browser management
  - DFIR or security tooling
- Review whether the process is on an allowlist or commonly used in your environment.

### 5. Search for broader compromise indicators
- Look for:
  - credential dumping
  - persistence creation
  - malicious downloads
  - browser-to-script execution
  - scheduled task or service creation
  - unusual logons after the event

## Common Benign Explanations
- Approved backup or forensic tooling
- Browser repair or profile migration utilities
- Enterprise browser management
- Security tools inspecting browser artifacts

## Escalate When
Escalate if:
- the accessing process is unknown, unsigned, or suspicious
- the process runs from a writable path
- multiple credential store files are accessed together
- the activity is followed by archiving or external transfer
- the same host shows infostealer, script, or persistence behavior
- the user is not associated with forensics or browser management activity

## Suggested Response Actions
- Preserve file and process telemetry around the event
- Acquire the binary or script responsible for the access
- Isolate the host if malicious collection is confirmed
- Review potentially exposed browser-based accounts and sessions
- Force session invalidation or password resets where appropriate
- Search the environment for the same process, path, or hash

## Analyst Notes
This is a strong credential-access analytic when paired with staging or exfiltration signals. By itself it can still produce benign hits from enterprise or forensic tooling, so process identity and environment context matter a lot.