# Triage Guide: LDAP Enumeration Using PowerShell

## Detection Title
LDAP Enumeration Using PowerShell

## Objective

This detection identifies PowerShell-based LDAP or Active Directory enumeration activity that may be used to collect information about users, groups, computers, trusts, or organizational structure.

## Why It Matters

LDAP and AD enumeration are common attacker discovery activities used to:
- identify users and privileged accounts
- discover groups and roles
- locate servers or domain controllers
- map trust relationships
- prepare for lateral movement or privilege escalation

PowerShell-based LDAP enumeration is especially important when used from non-admin hosts or by users who do not normally perform directory queries.

## Alert Logic Summary

The rule is intended to identify PowerShell commands or patterns associated with LDAP / AD enumeration, such as:
- `[ADSISearcher]`
- `Get-ADUser`
- `Get-ADComputer`
- `Get-ADGroup`
- LDAP query strings
- PowerShell-based directory search methods

## Initial Triage Questions

- Was the query executed by an admin, engineer, or normal user?
- Was the host expected to perform directory administration?
- Was the PowerShell use interactive, scripted, or remote?
- Did the same session include account enumeration or privileged-group discovery?
- Was the activity followed by authentication attempts or remote execution?

## Investigation Steps

1. Review the full PowerShell command line.
2. Identify the executing account and host type.
3. Determine the scope of enumeration:
   - users
   - groups
   - computers
   - trusts
   - domain structure
4. Check whether the activity aligns with the user’s normal role.
5. Review surrounding PowerShell activity for:
   - encoded commands
   - AMSI or logging tampering
   - remote execution
   - credential access
6. Review whether the same host or account later attempted:
   - NTLM auth probing
   - WMI / PSRemoting
   - group membership enumeration
   - admin share access

## Common False Positives

- legitimate AD administration
- identity engineering workflows
- PowerShell-based inventory scripts
- help desk scripts
- authorized security assessments

## Escalation Guidance

Escalate when:
- the activity is from a non-admin workstation
- the user is not expected to enumerate AD
- the activity appears broad or scripted
- it is followed by credential access or lateral movement
- the PowerShell execution context is suspicious

## Recommended Enrichment

- full command line
- PowerShell script block logs if available
- user role and privilege level
- host role
- parent process
- subsequent logon or remote execution activity
- related group / trust / account discovery commands

## ATT&CK Mapping

- Discovery
- T1087 – Account Discovery
- T1069 – Permission Group Discovery
- T1482 – Domain Trust Discovery
- T1018 / T1082 depending on scope

## Related Rule

- `detections/sentinel/discovery/ldap-enumeration-using-powershell.yml`