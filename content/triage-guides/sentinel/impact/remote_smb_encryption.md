# Triage Guide: Potential Remote SMB Encryption From Single Source Host

## What this detects
A single source host touching large numbers of files over SMB in a short period.

## Why it matters
This can reflect remote encryption from an unmanaged or lightly monitored system.

## Immediate questions
1. Which source IP or host is driving the SMB activity?
2. Is the source a sanctioned backup, migration, or deployment tool?
3. Are many files being renamed, rewritten, or replaced?
4. Is there evidence of ransom note creation or extension changes?

## Investigative steps
- Identify the source host and account behind the SMB activity.
- Validate whether the source host is managed and has EDR coverage.
- Review SecurityEvent 5140 and 5145 patterns across shares and targets.
- Look for simultaneous ransomware indicators on the source device.
- Review network and authentication logs for lateral movement into the source.

## Escalation indicators
- Unmanaged source device
- Many share targets in minutes
- File rename or overwrite bursts
- Ransom notes or suspicious extensions

## Likely false positives
- Enterprise backup jobs
- Bulk migration or file synchronization
- Large software deployment workflows
