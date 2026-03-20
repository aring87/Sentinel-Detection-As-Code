# Detection Engineering Program Charter

## Program Name

Detection Engineering Program

---

## Purpose

The Detection Engineering Program exists to design, govern, maintain, and improve security detections as a managed engineering capability.

The program provides a structured approach for turning threat-informed use cases, operational lessons learned, and telemetry opportunities into measurable detection content that supports the Security Operations Center (SOC), incident response, threat hunting, and leadership visibility.

---

## Mission

To build and sustain a repeatable, threat-informed, and measurable detection engineering capability that improves the organization’s ability to detect meaningful adversary behavior while reducing noise and increasing operational clarity.

---

## Vision

To establish a mature detection engineering function that treats detections as governed, tested, documented, and continuously improved engineering artifacts rather than ad hoc alert logic.

---

## Objectives

The program is intended to:

- improve visibility into attacker behaviors across enterprise environments
- build detections as code using standardized schemas and workflows
- align detections to MITRE ATT&CK and operational use cases
- provide triage guidance and documentation to support analysts
- create measurable reporting for leadership and stakeholders
- improve quality, consistency, and lifecycle management of detections
- establish a scalable foundation for validation, automation, and continuous improvement

---

## Scope

### In Scope
The program includes:
- detection strategy and planning
- detection content development
- rule metadata and documentation standards
- ATT&CK and Cyber Kill Chain mapping
- lifecycle management
- triage guide development
- coverage tracking and reporting
- governance standards
- tracking matrices and program reporting
- future validation and CI/CD workflows

### Out of Scope
The program does not directly replace:
- full incident response operations
- all SOC workflow ownership
- threat intelligence production
- platform administration responsibilities unrelated to detection content
- non-security monitoring content unless explicitly adopted into scope

---

## Stakeholders

Key stakeholders may include:
- Detection Engineering
- SOC Analysts
- Incident Response
- Threat Hunting / Purple Team
- Security Leadership
- Platform Owners
- Governance or Compliance stakeholders, where applicable

---

## Program Functions

The program performs the following core functions:

### 1. Detection Planning
Identify, prioritize, and document detection opportunities.

### 2. Detection Development
Create and maintain detections as code with standard metadata.

### 3. Documentation
Maintain triage guides, process documents, and reporting artifacts.

### 4. Governance
Enforce naming, lifecycle, severity, tagging, and quality standards.

### 5. Coverage Management
Track ATT&CK and use case coverage, including identified gaps.

### 6. Reporting
Provide structured reporting to leadership and operational stakeholders.

### 7. Continuous Improvement
Improve detections based on incidents, feedback, hunts, and lessons learned.

---

## Guiding Principles

The program operates according to these principles:

### Threat-Informed
Content should focus on meaningful attacker behavior and mission-relevant risk.

### Repeatable
Work should be standardized through templates, process documents, and governance.

### Explainable
Detections should be understandable to engineers, analysts, and leadership.

### Measurable
The program should show progress through coverage, lifecycle, and maturity reporting.

### Sustainable
Content should be maintainable over time with clear ownership and documentation.

### Collaborative
The program should incorporate feedback from SOC, IR, hunting, and leadership.

---

## Success Criteria

Examples of success indicators include:
- increased detection coverage across priority ATT&CK tactics
- more detections with complete metadata and documentation
- improved consistency of rule quality and lifecycle assignment
- more triage-ready content for analysts
- stronger visibility into content gaps and roadmap priorities
- a defined foundation for future validation and automation maturity

---

## Governance Alignment

This charter is supported by repository content that defines:
- operating model
- detection lifecycle
- exception management
- change control
- data source catalog
- reporting templates
- tracking matrix and triage guides

Together, these artifacts provide the operational foundation for the program.

---

## Repository Role

This repository serves as the central location for:
- program strategy
- governance documentation
- detection content
- tracking and reporting
- reusable templates
- future validation and automation workflows

It is intended to act as the system of record for detection engineering documentation and content development.

---

## Charter Review

This charter should be reviewed periodically to ensure it remains aligned with:
- program scope
- stakeholder needs
- platform changes
- reporting expectations
- detection engineering maturity goals