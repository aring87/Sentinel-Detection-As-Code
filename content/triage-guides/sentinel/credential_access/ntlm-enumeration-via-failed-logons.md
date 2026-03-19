# Triage Guide: NTLM Enumeration via Failed Logons

## Detection Title
NTLM Enumeration via Failed Logons

## Detection ID
dodea-sig-012-ntlm-enumeration-via-failed-logons

## Objective

This detection identifies repeated NTLM failed logon activity over a short period, which may indicate account enumeration, password spraying, or unauthorized authentication probing.

## Why It Matters

Repeated failed NTLM logons can reflect:
- account discovery
- password guessing
- password spraying
- misconfigured services repeatedly failing authentication

The key triage task is to determine whether the activity is malicious probing or a benign but broken authentication process.

## Alert Logic Summary

The rule looks for:
- `DeviceLogonEvents`
- `Protocol =~ "NTLM"`
- `ActionType =~ "LogonFailed"`

It summarizes failed attempts by:
- `DeviceName`
- `RemoteIP`
- time window

and alerts when attempts exceed a threshold.

## Initial Triage Questions

- What source IP generated the failures?
- How many unique accounts were targeted?
- Was the source an endpoint, server, scanner, or infrastructure system?
- Did any successful logons follow the failed attempts?
- Is the source associated with a known service misconfiguration?

## Investigation Steps

1. Review the source IP and affected device.
2. Determine whether the source is internal, external, or infrastructure-related.
3. Review the targeted accounts:
   - are they random?
   - are they privileged?
   - do they follow a naming pattern?
4. Check whether any successful NTLM logons occurred after the failed attempts.
5. Review whether the source host shows:
   - PowerShell activity
   - lateral movement
   - service account misuse
   - remote task creation
6. Determine whether a known service, script, or stale credential could explain the failures.

## Common False Positives

- misconfigured services
- stale credentials in scheduled tasks or scripts
- broken service-account authentication
- testing or simulation exercises
- legacy systems retrying NTLM auth

## Escalation Guidance

Escalate when:
- many distinct accounts are targeted
- the source IP or device is suspicious or compromised
- successful authentication follows the failures
- privileged or sensitive accounts are involved
- the pattern resembles password spraying rather than service failure

## Recommended Enrichment

- source IP history
- targeted account list
- successful logons after failures
- device role and owner
- related endpoint detections on the source host
- service account inventory if relevant
- timeline of repeated failures

## ATT&CK Mapping

- Credential Access
- T1110.003 – Brute Force: Password Spraying

## Related Rule

- `detections/sentinel/credential-access/ntlm-enumeration-via-failed-logons.yml`