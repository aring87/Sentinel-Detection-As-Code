# VSSAdmin Delete Shadows

## Goal
Identify use of `vssadmin.exe` to delete shadow copies.

## Why This Alert Matters
`vssadmin.exe delete shadows` is a classic ransomware and destructive-activity command used to inhibit recovery.

## What the Detection Is Looking For
This detection looks specifically for:
- `vssadmin.exe`
- command lines containing `delete shadows`

## Likely ATT&CK Mapping
- T1490 – Inhibit System Recovery

## Initial Triage Questions
1. Was `vssadmin.exe` authorized on this host?
2. Who launched it and from what parent process?
3. Is there evidence of encryption or other destructive behavior nearby?

## Investigation Steps
- Review the full command line.
- Review the initiating account and process lineage.
- Correlate with mass file modifications, ransom notes, and recovery tampering.
- Determine whether this should be retired in favor of the broader standardized shadow-copy-deletion guide.

## Common Benign Explanations
- Rare admin maintenance
- Recovery testing
- Lab usage

## Escalate When
Escalate if the command is unexplained, suspiciously launched, or paired with other ransomware indicators.

## Suggested Response Actions
- preserve the command execution evidence
- check for broader impact behavior
- contain the host if destructive activity is active

## Analyst Notes
This is best treated as a legacy or compatibility guide. Prefer the broader `volume-shadow-copy-deletion` guide for primary triage.