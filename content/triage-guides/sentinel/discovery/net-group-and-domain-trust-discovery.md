# Triage Guide: Net Group and Domain Trust Discovery

## Detection Title
Net Group and Domain Trust Discovery

## Objective

This detection identifies use of commands associated with group enumeration, domain trust discovery, and related domain reconnaissance.

## Why It Matters

Attackers use group and trust discovery to:
- identify privileged groups
- understand domain relationships
- map administrative boundaries
- identify paths for lateral movement
- identify high-value identity targets

This type of activity is especially relevant in enterprise and domain environments.

## Alert Logic Summary

The rule is intended to identify execution of commands such as:
- `net group`
- `net group /domain`
- `nltest`
- trust-discovery-related commands
- similar domain-recon patterns

## Initial Triage Questions

- Was the command focused on local groups, domain groups, or trust relationships?
- Is the user expected to perform domain administration?
- Did the host also show other AD or account discovery activity?
- Did the same session include remote admin or credential access behavior?
- Was the activity interactive or launched by a script/tool?

## Investigation Steps

1. Review the full command line.
2. Identify whether the target was:
   - domain groups
   - admin groups
   - trust relationships
   - domain metadata
3. Review the executing account and host.
4. Determine whether the activity aligns with normal IT/admin duties.
5. Review nearby activity for:
   - `net user`
   - `whoami /groups`
   - PowerShell AD enumeration
   - `dsquery`
   - `nltest /domain_trusts`
6. Check for follow-on signs of:
   - privileged access attempts
   - lateral movement
   - share enumeration
   - service or task creation

## Common False Positives

- domain administration
- troubleshooting trust issues
- identity engineering work
- server onboarding / migration activity
- approved security validation

## Escalation Guidance

Escalate when:
- the user is not expected to perform domain discovery
- the command targets privileged groups or trust relationships
- the host is a normal workstation
- the activity is part of a broader discovery burst
- it is followed by authentication or movement attempts

## Recommended Enrichment

- full command line
- queried group / trust details
- user role
- host sensitivity
- adjacent discovery commands
- related authentication events
- parent process / script context

## ATT&CK Mapping

- Discovery
- T1069 – Permission Group Discovery
- T1482 – Domain Trust Discovery

## Related Rule

- `detections/sentinel/discovery/net-group-and-domain-trust-discovery.yml`