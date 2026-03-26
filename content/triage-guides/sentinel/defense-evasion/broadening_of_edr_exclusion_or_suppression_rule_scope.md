# Broadening of EDR Exclusion or Suppression Rule Scope

## Goal
Identify suspicious security control changes where endpoint detection exclusions or suppression rules are expanded in scope in a way that could reduce visibility or protection.

## Why This Alert Matters
Attackers who gain administrative access often try to weaken defenses before running payloads, stealing credentials, or spreading laterally. Broadening an exclusion from a narrow path or user to a global scope can create a large blind spot and may indicate defense evasion. These changes are high impact because they affect future detections, not just the single host under review.

## What the Detection Is Looking For
This detection reviews configuration change telemetry for:
- actions such as:
  - `ExclusionModified`
  - `SuppressionRuleModified`
  - `DetectionPolicyChanged`
- new values indicating broad scope such as:
  - `All Users`
  - `*`
  - `Any User`
  - `Global`

## Likely ATT&CK Mapping
- T1562.001 – Impair Defenses: Disable or Modify Tools
- T1078 – Valid Accounts
- T1112 – Modify Registry or policy-like security configuration context

## Initial Triage Questions
1. What exclusion or suppression changed, and how broad is the new scope?
2. Who made the change, and do they normally administer the security platform?
3. Did the change happen shortly before suspicious execution, credential access, or ransomware behavior?
4. Was the change approved as part of a maintenance or tuning task?
5. Did the actor modify other security controls in the same timeframe?

## Key Fields To Review
- Timestamp
- EventType
- actor or admin account
- target policy name
- previous value
- new value
- device group or scope
- related ticket or change window if available

## Investigation Steps
### 1. Validate the policy change
- Determine exactly what setting changed.
- Compare:
  - previous scope
  - new scope
  - affected users or devices
  - justification or comment fields
- Identify whether the change materially weakens detection coverage.

### 2. Review the actor
- Confirm whether the actor is:
  - a security engineer
  - platform admin
  - service account
  - unexpected user
- Check authentication context and source IPs where available.

### 3. Correlate with surrounding activity
Look for:
- suspicious process execution
- ransomware indicators
- Defender tampering
- new persistence
- credential dumping
- other policy or identity changes by the same actor

### 4. Assess blast radius
- Identify how many:
  - devices
  - users
  - groups
  - paths
  - process names
  were affected by the broader exclusion.
- Determine whether critical assets became unprotected.

### 5. Validate business context
- Confirm whether the change aligns with:
  - false-positive tuning
  - emergency support
  - new software rollout
  - approved security engineering maintenance
- If legitimate, verify that the broader scope was truly necessary.

## Common Benign Explanations
- Approved false-positive tuning
- Planned software rollout requiring temporary exclusions
- Platform maintenance by security engineering
- Emergency troubleshooting for a known bad interaction

## Escalate When
Escalate if:
- the scope expanded from narrow to effectively global
- the actor is not a normal security platform admin
- the change coincided with suspicious execution or ransomware activity
- critical assets or many users were affected
- there is no approved ticket or documented reason

## Suggested Response Actions
- preserve policy audit records and before/after values
- revert or narrow the exclusion if unauthorized
- review detections and alerts suppressed during the affected window
- hunt for suspicious activity that may have been hidden by the change
- notify security platform owners and incident response

## Analyst Notes
Control-plane changes in EDR platforms can be just as important as endpoint detections themselves. A broad exclusion may be the enabling step that explains why later malicious activity had limited visibility.
