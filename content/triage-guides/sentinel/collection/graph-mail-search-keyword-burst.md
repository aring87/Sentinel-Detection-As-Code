# Microsoft Graph Mail Access Burst Triage Guide

## Rule Overview

**Title:** Microsoft Graph Mail Access Burst  
**Rule ID:** SENT-COLL-0004  
**Severity:** Medium  
**Risk Score:** 70  
**Tactic:** Collection  
**Technique:** T1114 - Email Collection  
**Platform:** Microsoft Sentinel  
**Data Source:** CloudAppEvents  
**Lifecycle:** Experimental

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

- 30-minute window
- user
- application

The rule alerts when the action count reaches 20 or more within the window.

## Likely Analyst Goal

Determine whether the burst of Graph mail access was:

- Approved admin, migration, journaling, or eDiscovery activity
- Legitimate application integration behavior
- Suspicious mailbox reconnaissance or collection after identity compromise

## Initial Triage Questions

1. Which user or application performed the mail access?
2. Is this volume of Graph mail activity normal?
3. Was the activity tied to a known tenant application or integration?
4. Were there recent risky sign-ins, device code sign-ins, or consent events?
5. Did the activity target high-value mailboxes or lead to forwarding, export, or download behavior?

---

## Investigation Steps

### 1. Validate the User or Application Context

Review:

- User identity
- Account type
- Associated application
- Source IP addresses

Determine whether the activity came from:

- A human user
- A service principal
- An approved integration
- An unknown or suspicious application workflow

**Why this matters:**  
Graph access by approved enterprise applications is common, but unexpected users or apps can indicate abuse.

---

### 2. Review the Volume and Timing

Assess:

- Number of actions
- Time window
- Types of actions observed
- Whether the burst is isolated or recurring

Determine whether the pattern suggests:

- Routine application polling
- Large-scale mail review
- Sudden collection after sign-in
- Unusual mailbox targeting

**Why this matters:**  
A concentrated burst of mail access can indicate targeted collection or reconnaissance.

---

### 3. Review Authentication and Identity Signals

Check for nearby:

- Device code sign-ins
- Risky sign-ins
- Unfamiliar IP addresses
- Impossible travel
- MFA changes
- OAuth abuse indicators
- Consent grants

**Why this matters:**  
Mailbox collection often follows identity compromise or OAuth abuse.

---

### 4. Determine Whether the Activity Is Approved

Validate whether the activity aligns to:

- Migration tools
- eDiscovery workflows
- Journaling solutions
- Mail security products
- Approved enterprise applications
- Known automation

**Why this matters:**  
Some applications legitimately access mailbox data at scale.

---

### 5. Check for High-Value or Targeted Mailbox Access

Determine whether the activity involved:

- Executives
- Finance
- HR
- Legal
- Admins
- Sensitive shared mailboxes

Also assess whether the user accessed:

- Their own mailbox only
- Multiple mailboxes
- Unexpected high-value targets

**Why this matters:**  
Targeting sensitive mailboxes can indicate focused intelligence gathering.

---

### 6. Review for Follow-On Collection or Exfiltration

Look for nearby indicators such as:

- Mail export
- Forwarding rule creation
- Inbox rule changes
- Download behavior
- Additional Graph enumeration
- SharePoint or OneDrive access bursts

**Why this matters:**  
Mail access becomes more serious when followed by export, forwarding, or broader cloud collection.

---

## Benign Explanations

Common legitimate scenarios include:

1. Migration tools
2. eDiscovery, journaling, or approved admin search workflows
3. Application integrations that legitimately access mail at scale

---

## Suspicious Indicators

Escalate concern when you observe:

- Graph mail access by an unusual user or app
- Device code or risky sign-ins nearby
- New or suspicious consent grants
- Access from unfamiliar IP addresses
- Multiple sensitive mailboxes accessed
- Follow-on export, forwarding, or download activity

---

## Triage Decision

### Close as Benign / False Positive

Close as benign when:

- The user or application is approved
- Activity matches known admin or business workflows
- No suspicious sign-in or follow-on behavior is observed

### Escalate as Suspicious

Escalate when:

- The access burst is unusual for the user or app
- Identity anomalies are present
- High-value mailboxes were touched
- Follow-on collection behavior is suspected

### Escalate as Likely Malicious

Escalate as likely malicious when:

- Evidence supports OAuth abuse or compromised credentials
- Sensitive mailbox access is unexplained
- Export, forwarding, or additional collection is confirmed

---

## Response Actions

Depending on findings, consider:

- Disabling or restricting the affected account or application
- Revoking tokens or OAuth grants
- Reviewing mailbox audit logs
- Investigating related cloud collection activity
- Escalating to incident response for suspected mailbox compromise

---

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
