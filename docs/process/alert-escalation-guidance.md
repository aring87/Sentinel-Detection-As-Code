# Alert Escalation Guidance

## Purpose

This document defines general escalation guidance for detections managed within the detection engineering program.

The goal is not to replace case-specific procedures, but to provide a common framework for when a detection should remain in triage versus when it should be escalated for deeper investigation or incident response.

---

## General Principle

Escalation decisions should be based on:
- the nature of the behavior detected
- supporting evidence available
- confidence that the activity is suspicious or malicious
- the impact of the affected host, identity, or system
- related activity observed around the alert

---

## Reasons to Escalate

An alert should generally be considered for escalation when one or more of the following are true:

### High-Risk Behavior
The activity strongly aligns with known malicious behavior or high-value attacker tradecraft.

### Sensitive Account or Asset Involvement
The alert involves:
- privileged accounts
- critical systems
- sensitive servers
- high-value users
- externally exposed assets

### Supporting Correlation Exists
The same host, account, or process also shows related suspicious activity.

### Clear Malicious Context Exists
The evidence includes obviously suspicious or malicious context, such as:
- encoded script execution
- credential dumping behavior
- unusual persistence creation
- suspicious remote execution
- destructive commands

### Triage Cannot Confidently Explain the Activity
The analyst cannot reasonably attribute the activity to expected or approved behavior.

---

## Reasons to Keep in Triage

An alert may remain in triage when:
- the behavior appears consistent with expected administration
- the involved account, process, or host is known-good
- the detection lacks sufficient evidence for escalation
- the event appears isolated and benign after review
- the guide or detection notes identify a common benign explanation

---

## Escalation Questions

Analysts should ask:
- what exactly happened?
- who performed the action?
- where did it occur?
- is the behavior expected in this environment?
- is there related suspicious activity?
- what is the potential impact if malicious?
- is the affected system or account high-value?

---

## Escalation Inputs

Useful escalation context may include:
- affected host
- user or account
- parent and child processes
- full command line
- registry or file path context
- network destination context
- related alerts
- timeline of surrounding activity

---

## Escalation Outcomes

Possible outcomes include:
- close as benign
- document as expected activity
- monitor for recurrence
- escalate to incident response
- create follow-up hunt
- request detection improvement or triage guide enhancement

---

## Repository Relationship

This guidance supports:
- triage guide development
- severity review
- lifecycle maturity
- SOC / IR alignment
- continuous detection improvement

---

## Summary

Alert escalation guidance helps create a shared baseline for interpreting detection outcomes and deciding when analyst triage should transition into deeper investigative or incident response activity.
