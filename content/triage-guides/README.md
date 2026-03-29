# Triage Guides

This directory contains analyst-facing triage guides that support the operational use of detections in the repository.

These guides are intended to make detections easier to understand, easier to investigate, and more consistent to triage across analysts, responders, and engineering teams.

## Purpose

Triage guides help SOC analysts and incident responders understand:

- what a detection is intended to identify
- why the alert matters
- what questions to ask first
- what evidence to review
- what investigation path to follow
- what common benign explanations may exist
- when escalation is appropriate
- what response actions may be needed

The goal is to make detections more actionable and easier to investigate consistently.

## Structure

### Priority Starter Rules
- [Priority Starter Rules](priority-starter-rules/)

These guides support the highest-priority starter detections currently included in the repository and provide a practical starting point for operational detection coverage.

## What a Triage Guide Should Include

A strong triage guide should usually contain:

- detection title
- goal or objective
- why the alert matters
- detection logic summary
- likely ATT&CK mapping
- initial triage questions
- key fields to review
- step-by-step investigation guidance
- common benign explanations
- escalation guidance
- suggested response actions
- analyst notes where useful

## Intended Audience

These guides are primarily intended for:

- SOC analysts
- incident responders
- detection engineers reviewing analyst usability
- threat hunters who need quick operational context

## Relationship to Detection Engineering

Triage guides are an important part of detection maturity.

A detection is more operationally useful when analysts can quickly understand:

- what it means
- how to investigate it
- when it is likely benign
- when it should be escalated
- what supporting evidence should be collected

Strong triage content helps connect detection logic to real operational use.

## Goal

The goal of this directory is to improve:

- analyst usability
- investigation consistency
- operational readiness
- escalation quality
- the overall value of detection content in production use

## Related Content

- [Detection Rule Template](../templates/detection-rule-template.yml)
- [Triage Guide Template](../templates/triage-guide-template.md)
- [Detection Tracking Matrix](../../docs/04_reporting/detection_tracking_matrix.csv)
- [Detection Lifecycle](../../docs/02_process/detection-lifecycle.md)