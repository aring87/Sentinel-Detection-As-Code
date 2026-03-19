# Triage Guide: Suspicious Browser Credential Store Access

## Detection Title
Suspicious Browser Credential Store Access

## Detection ID
SENT-CRED-0003

## Objective

This detection identifies non-browser processes accessing browser credential stores such as Chrome, Edge, or Firefox profile data. This may indicate credential theft, session theft, or collection of saved login material.

## Why It Matters

Browser credential stores may contain:
- saved usernames and passwords
- cookies
- session tokens
- profile data useful for account hijacking

Access by non-browser processes is often unusual and can be an indicator of credential theft or post-compromise collection.

## Alert Logic Summary

The rule looks for:
- `DeviceFileEvents`
- access to browser credential-store paths such as:
  - Chrome `Login Data`
  - Edge `Login Data`
  - Firefox profile folders
- initiating processes that are not:
  - `chrome.exe`
  - `msedge.exe`
  - `firefox.exe`

## Initial Triage Questions

- What non-browser process accessed the credential store?
- Is the process approved, signed, or enterprise-managed?
- Was the host under backup, migration, or forensic activity?
- Did the same process also archive or transfer files?
- Was the access isolated or repeated?

## Investigation Steps

1. Review the initiating process name, path, and signer.
2. Determine whether the process is approved in the environment.
3. Identify the user context and host role.
4. Review whether the process also touched:
   - cookies
   - browser profile data
   - archive files
   - temp or staging locations
5. Look for related behavior:
   - compression
   - cloud uploads
   - external network connections
   - credential or token abuse
6. Determine whether backup, migration, or repair utilities explain the access.

## Common False Positives

- profile migration tools
- browser repair utilities
- approved backup tools
- forensics or IR tooling
- enterprise management software

## Escalation Guidance

Escalate when:
- the process is unsigned, unknown, or suspicious
- browser credential stores are accessed along with archive creation or transfer
- the same process touches multiple user credential stores
- the host is high-value or privileged
- the activity cannot be explained by approved software

## Recommended Enrichment

- initiating process path and signer
- parent process
- file access timeline
- archive creation telemetry
- network/exfiltration activity
- user role and host sensitivity
- related alerts on the same device

## ATT&CK Mapping

- Credential Access
- T1555.003 – Credentials from Web Browsers

## Related Rule

- `detections/sentinel/credential-access/suspicious-browser-credential-store-access.yml`