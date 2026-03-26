# Graph Mail Access Burst Triage Guide

## Rule Overview

**Title:** Microsoft Graph Mail Access Burst  
**Rule ID:** SENT-COLL-0004  
**Status:** Experimental  
**Severity:** Medium  
**Risk Score:** 70  
**Tactic:** Collection  
**Technique:** T1114 - Email Collection  
**Platform:** Microsoft Sentinel  
**Data Source:** CloudAppEvents

## Purpose

This detection identifies bursts of Microsoft Graph mail search or mail access activity that may indicate post-compromise mailbox collection or reconnaissance.

This matters because attackers with cloud access may use Microsoft Graph to:

- Search mailbox contents
- Read emails at scale
- Collect sensitive communications
- Enumerate high-value targets
- Prepare for theft, extortion, or further compromise

## Detection Logic Summary

The rule reviews `CloudAppEvents` where:

- `Application == "Microsoft Graph"`
- `ActionType` includes:
  - `SearchQueryPerformed`
  - `MailItemsAccessed`
  - `MessageBind`

It summarizes activity by:

- 30-minute time window
- user
- application

The rule alerts when:

- `ActionCount >= 20`

It also captures:

- action types observed
- source IPs associated with the activity

## Likely Analyst Goal

Determine whether the Graph mail access burst was:

- Approved admin, migration, journaling, or eDiscovery activity
- Legitimate application integration behavior
- Suspicious mailbox reconnaissance or collection after identity compromise

## Initial Triage Questions

1. Which user or application performed the mail access?
2. Is this level of Graph mail activity normal for that identity?
3. Was the activity tied to a known tenant application or integration?
4. Were there nearby risky sign-ins, device code sign-ins, consent grants, or OAuth abuse indicators?
5. Did the activity target high-value mailboxes or lead to export, forwarding, or download behavior?

---

## Investigation Steps

### 1. Validate the User or Application Context

Review:

- user identity
- account type
- associated application
- source IP addresses

Determine whether the activity came from:

- a human user
- a service principal
- an approved integration
- an unknown or suspicious application flow

**Why this matters:**  
Graph access by approved enterprise applications can be normal, but unexpected users or apps can indicate abuse.

---

### 2. Review the Volume and Timing of Activity

Assess:

- total number of actions
- action types observed
- time window of activity
- whether the burst is isolated or recurring

Determine whether the pattern suggests:

- routine application polling
- large-scale mailbox review
- sudden collection after sign-in
- targeted mailbox reconnaissance

**Why this matters:**  
A concentrated burst of mail access can indicate focused collection or reconnaissance.

---

### 3. Review Authentication and Identity Signals

Check for nearby:

- device code sign-ins
- risky sign-ins
- unfamiliar IP addresses
- impossible travel
- MFA changes
- consent grants
- OAuth abuse indicators

**Why this matters:**  
Mailbox collection often follows identity compromise or unauthorized OAuth access.

---

### 4. Determine Whether the Activity Is Approved

Validate whether the activity aligns to:

- migration tools
- eDiscovery workflows
- journaling solutions
- mail security products
- approved enterprise applications
- known automation

**Why this matters:**  
Some applications legitimately access mailbox data at scale and can resemble suspicious behavior.

---

### 5. Check for High-Value or Targeted Mailbox Access

Determine whether the activity involved:

- executives
- finance
- HR
- legal
- admins
- sensitive shared mailboxes

Also assess whether the identity accessed:

- only its own mailbox
- multiple mailboxes
- unexpected high-value targets

**Why this matters:**  
Targeting sensitive mailboxes can indicate focused intelligence gathering or theft.

---

### 6. Review for Follow-On Collection or Exfiltration

Look for nearby indicators such as:

- mail export
- forwarding rule creation
- inbox rule changes
- download behavior
- additional Graph enumeration
- SharePoint or OneDrive access bursts

**Why this matters:**  
Mail access becomes much more serious when followed by export, forwarding, or broader cloud collection activity.

---

## Benign Explanations

Common legitimate scenarios include:

1. Migration tools
2. eDiscovery, journaling, or approved admin search workflows
3. Application integrations that legitimately access mail at scale

## Suspicious Indicators

Escalate concern when you observe:

- Graph mail access by an unusual user or app
- device code or risky sign-ins nearby
- new or suspicious consent grants
- access from unfamiliar IP addresses
- multiple sensitive mailboxes accessed
- follow-on export, forwarding, or download behavior

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- the user or application is approved
- the activity matches known admin or business workflows
- no suspicious sign-in or follow-on behavior is observed

### Escalate as Suspicious

Escalate when:

- the access burst is unusual for the identity or app
- identity anomalies are present
- high-value mailboxes were touched
- follow-on collection behavior is suspected

### Escalate as Likely Malicious

Escalate as likely malicious when:

- evidence supports OAuth abuse or compromised credentials
- sensitive mailbox access is unexplained
- export, forwarding, or additional collection is confirmed

## Response Actions

Depending on findings, consider:

- restricting or disabling the affected account or application
- revoking tokens or OAuth grants
- reviewing mailbox audit logs
- investigating related cloud collection activity
- escalating to incident response for suspected mailbox compromise

## Example Analyst Notes Template

### Analyst Summary

Alert fired for a burst of Microsoft Graph mail access activity, potentially indicating mailbox reconnaissance or collection.

### Key Findings

- **Affected user or application:**  
- **Source IPs:**  
- **Action volume:**  
- **Action types:**  
- **Expected business purpose:**  
- **Risky sign-in or consent activity:**  
- **High-value mailbox access:**  
- **Follow-on export or forwarding behavior:**  
- **Final assessment:**  

### Recommended Disposition

- Benign / False Positive
- Suspicious - Needs Deeper Investigation
- Confirmed Malicious

## Validation Guidance

Tune thresholds against known mail clients, admin workflows, and approved tenant applications so legitimate Graph-heavy integrations do not overwhelm the rule.
