# Triage Guide: Net User Enumeration

## Detection Title
Net User Enumeration

## Objective

This detection identifies use of `net user` and related commands to enumerate local or domain user accounts.

## Why It Matters

Account enumeration is a common discovery step used to:
- identify valid usernames
- identify privileged or service accounts
- prepare for password spraying
- prepare for lateral movement
- validate targeting opportunities

This command is legitimate in administration, but it is also frequently used by attackers after initial access.

## Alert Logic Summary

The rule is intended to identify use of:
- `net user`
- `net user /domain`
- related account-discovery commands

## Initial Triage Questions

- Who ran `net user`?
- Was it run on a workstation, server, or admin host?
- Was the command local-only or domain-focused?
- Does the user normally perform account administration?
- Were there additional discovery commands nearby?

## Investigation Steps

1. Review the full command line.
2. Identify whether the query targeted:
   - local users
   - domain users
3. Determine the user and host context.
4. Review neighboring process activity for:
   - `net group`
   - `whoami`
   - `nltest`
   - `dsquery`
   - PowerShell AD queries
5. Check whether the same account or host later attempted:
   - failed logons
   - remote execution
   - privilege escalation
6. Determine whether the activity was interactive or launched from a script/tool.

## Common False Positives

- legitimate admin troubleshooting
- help desk checks
- server build/configuration workflows
- account administration scripts

## Escalation Guidance

Escalate when:
- the activity is performed by a non-admin user
- it originates from a suspicious or recently compromised host
- it is one step in a larger discovery burst
- it is followed by password spraying or lateral movement
- the user cannot explain the action

## Recommended Enrichment

- full command line
- user account and privilege level
- host type
- nearby discovery commands
- related failed/successful logons
- parent process
- interactive vs scripted execution context

## ATT&CK Mapping

- Discovery
- T1087 – Account Discovery

## Related Rule

- `detections/sentinel/discovery/net-user-enumeration.yml`