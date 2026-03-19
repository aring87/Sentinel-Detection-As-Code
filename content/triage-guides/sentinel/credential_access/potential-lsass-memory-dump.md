# Triage Guide: Potential LSASS Memory Dump

## Detection Title
Potential LSASS Memory Dump

## Detection ID
SENT-CRED-0002

## Objective

This detection identifies common command lines and tooling associated with dumping LSASS memory, including references to `MiniDumpWriteDump`, `comsvcs.dll`, `procdump`, `sekurlsa`, and `lsass`.

## Why It Matters

Dumping LSASS memory is a high-value credential-theft behavior that can enable extraction of:
- usernames and passwords
- NTLM hashes
- Kerberos tickets
- privileged account material

This is one of the strongest credential-access indicators in a Windows environment.

## Alert Logic Summary

The rule looks for command lines containing:
- `lsass`
- `MiniDumpWriteDump`
- `comsvcs.dll, MiniDump`
- `procdump`
- `sekurlsa`

It projects process and parent-process context for review.

## Initial Triage Questions

- Which utility or command pattern was used?
- Was the host under authorized memory analysis or EDR activity?
- Was a dump file written to disk?
- Did the process run as a privileged user or SYSTEM?
- Was the dump followed by lateral movement or exfiltration behavior?

## Investigation Steps

1. Review the full command line and binary path.
2. Identify the process, parent process, and account.
3. Determine whether a dump file was created and where.
4. Check for known security tooling or approved IR workflows.
5. Review for related activity:
   - token abuse
   - privilege escalation
   - suspicious remote execution
   - archive creation
   - external communications
6. Assess the host sensitivity and whether credentials from that host would be high value.

## Common False Positives

- approved EDR actions
- memory forensics
- authorized security testing
- incident response collection

## Escalation Guidance

Escalate when:
- the activity is not clearly authorized
- dump creation is confirmed
- the host is privileged, sensitive, or a jump/admin system
- there is related suspicious execution or movement
- the process comes from an unusual path or unsigned tooling

## Recommended Enrichment

- dump file path
- process hash and signer
- parent process
- account privilege level
- related logons and remote admin activity
- file/archive activity after the dump
- network activity after the dump

## ATT&CK Mapping

- Credential Access
- T1003.001 – OS Credential Dumping: LSASS Memory

## Related Rule

- `detections/sentinel/credential-access/potential-lsass-memory-dump.yml`