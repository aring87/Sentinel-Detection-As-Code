# Triage Guide: LSASS Access Dumped with Mimikatz

## Detection Title
LSASS Access Dumped with Mimikatz

## Detection ID
dodea-sig-029-lsass-dump-mimikatz

## Objective

This detection identifies command-line activity referencing LSASS access or Mimikatz-style credential dumping behavior, especially use of terms such as `sekurlsa` or `lsass`.

## Why It Matters

Credential dumping from LSASS is a classic post-compromise technique used to extract:
- plaintext credentials
- NTLM hashes
- Kerberos tickets
- cached logon material

Any sign of Mimikatz-associated LSASS access is high-value and should be treated seriously unless clearly tied to approved testing or forensics.

## Alert Logic Summary

The rule looks for command lines containing:
- `sekurlsa`
- `lsass`

This is intended to identify process activity commonly associated with Mimikatz or related credential-dumping utilities.

## Initial Triage Questions

- What process generated the command line?
- Was Mimikatz or a similar tool actually present on the host?
- Was this activity part of approved red team, IR, or security testing?
- Was the user privileged?
- Were there nearby signs of privilege escalation or lateral movement?

## Investigation Steps

1. Review the full command line and process path.
2. Identify the parent process and execution chain.
3. Determine whether the binary or script is known, signed, or approved.
4. Review whether the same host showed:
   - privilege escalation
   - suspicious service or scheduled task creation
   - remote execution
   - outbound network connections
5. Check for dump-file creation or forensic artifacts on disk.
6. Review the user context, logon session, and host criticality.

## Common False Positives

- authorized red team activity
- approved security validation
- incident response or memory forensics tooling
- lab testing

## Escalation Guidance

Escalate when:
- the activity is not explicitly authorized
- Mimikatz-like tooling appears on a production system
- the host is privileged, sensitive, or domain-connected
- there is correlated lateral movement or persistence behavior
- the user cannot explain the activity

## Recommended Enrichment

- process tree
- full command line
- file hash and signer
- dump file path if created
- user privilege level
- related alerts on the same host
- network activity following the execution

## ATT&CK Mapping

- Credential Access
- T1003.001 – OS Credential Dumping: LSASS Memory

## Related Rule

- `detections/sentinel/credential-access/lsass-access-dumped-with-mimikatz.yml`