# Triage Guide: Potential NTLM Enumeration via Failed Logons

## Detection Title
Potential NTLM Enumeration via Failed Logons

## Detection ID
SENT-CRED-0001

## Objective

This detection identifies spikes in failed NTLM authentication attempts across multiple accounts, which may indicate account enumeration, password spraying, or broad authentication probing.

## Why It Matters

High-volume NTLM failures across many accounts can indicate:
- password spraying
- username discovery
- reconnaissance prior to exploitation
- compromised systems attempting wide authentication

The combination of failure count and number of targeted accounts makes this more concerning than isolated bad-password events.

## Alert Logic Summary

The rule looks for:
- `IdentityLogonEvents`
- `Protocol =~ "NTLM"`
- `ActionType =~ "LogonFailed"`

It summarizes by:
- `DeviceName`
- `IPAddress`
- time window

and alerts when both:
- total failures are high
- distinct targeted accounts are high

## Initial Triage Questions

- What source IP or device generated the activity?
- How many accounts were targeted?
- Were any targeted accounts privileged?
- Did any of the accounts later authenticate successfully?
- Is the activity consistent with a broken service or broad password spray?

## Investigation Steps

1. Review the source IP and associated host.
2. Review the set of targeted accounts for pattern and importance.
3. Determine whether the source is:
   - a user workstation
   - a server
   - a scan/test system
   - a misconfigured service host
4. Check for follow-on successful logons.
5. Review surrounding endpoint and identity activity on the source host.
6. Determine whether the same source has generated similar failures before.

## Common False Positives

- stale credentials
- misconfigured services
- broken authentication loops
- authorized password spray simulations
- legacy systems retrying incorrect NTLM auth

## Escalation Guidance

Escalate when:
- many unique accounts are targeted quickly
- successful auth follows the failures
- privileged accounts are included
- the source host shows other suspicious behavior
- the pattern resembles broad probing rather than normal service failure

## Recommended Enrichment

- list of targeted accounts
- source IP history
- successful auth after failures
- host inventory / ownership
- related identity alerts
- endpoint telemetry from the source device
- prior behavior from the same source

## ATT&CK Mapping

- Credential Access
- Reconnaissance
- T1110.003 – Brute Force: Password Spraying
- T1087 – Account Discovery

## Related Rule

- `detections/sentinel/credential-access/potential-ntlm-enumeration-via-failed-logons.yml`