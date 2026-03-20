# Detection Engineering Scope

## Purpose

This document defines the scope of the Detection Engineering Program, including what the program is responsible for, what it supports, and what remains outside its primary ownership.

Clear scope helps ensure the program remains focused, measurable, and aligned to stakeholder expectations.

---

## In Scope

The Detection Engineering Program includes the following areas:

### 1. Detection Strategy
- defining detection priorities
- identifying coverage goals
- aligning detections to ATT&CK and use cases
- supporting roadmap development

### 2. Detection Content Development
- authoring detections as code
- maintaining rule metadata
- organizing content in the repository
- standardizing detection schemas and formats

### 3. Detection Documentation
- triage guides
- rule notes
- lifecycle documentation
- reporting artifacts
- supporting process and governance documents

### 4. Detection Governance
- naming standards
- lifecycle standards
- severity guidance
- tagging guidance
- metadata quality expectations
- ownership expectations

### 5. Coverage Management
- ATT&CK mapping
- Cyber Kill Chain mapping
- coverage matrix maintenance
- gap identification
- roadmap-driven coverage expansion

### 6. Program Reporting
- metrics catalog
- tracking matrix
- quarterly review materials
- executive summaries and roadmap artifacts

### 7. Detection Lifecycle Management
- experimental
- testing
- production
- deprecated

### 8. Future Validation and Automation Foundations
- validation planning
- workflow quality checks
- CI/CD readiness planning
- structured content review support

---

## Supported Stakeholders

The program supports:
- detection engineers
- SOC analysts
- incident responders
- threat hunters
- security leadership
- platform owners
- governance stakeholders where applicable

---

## Out of Scope

The program does not directly own the following unless explicitly adopted into scope:

### 1. Incident Response Operations
The program supports IR through better content and lessons learned, but does not replace incident response responsibilities.

### 2. SOC Operations Management
The program improves analyst-facing content and workflows, but does not own day-to-day SOC operations unless separately assigned.

### 3. Threat Intelligence Production
Threat intelligence may inform the program, but the program does not inherently own intelligence collection or production.

### 4. General Platform Administration
The program may depend on detection platforms such as Sentinel or Splunk, but it does not automatically own all administrative tasks for those platforms.

### 5. Non-Security Monitoring
General IT operations monitoring, performance monitoring, and unrelated operational alerting are outside scope unless explicitly included.

### 6. Full Automation Engineering
The program may define automation requirements and future CI/CD workflows, but broad automation engineering may be handled separately depending on resources and maturity.

---

## Scope Boundaries

The program is primarily responsible for:
- what detections are built
- how they are documented
- how they are governed
- how they are tracked
- how they are organized and matured over time

The program is not solely responsible for:
- every operational action taken after an alert fires
- every telemetry onboarding decision
- every security platform configuration choice
- every investigative workflow outside detection content itself

---

## Scope Evolution

This scope may expand over time as the program matures.

Likely future expansions include:
- stronger validation ownership
- deeper automation support
- cross-platform detection engineering beyond Sentinel
- tighter integration with Splunk and other telemetry platforms
- more formal quality gates and reporting workflows

---

## Summary

The scope of detection engineering is to manage the strategy, governance, lifecycle, documentation, and development of detections as an engineering discipline, while supporting — but not fully replacing — adjacent operational and platform functions.