# Detection Engineering Operating Model

## Purpose

This operating model defines how the detection engineering program functions across strategy, content development, governance, validation, deployment, and reporting.

The goal is to establish a repeatable and scalable approach for building and maintaining high-quality detection content that supports SOC operations, threat-informed defense, and executive visibility.

---

## Objectives

The detection engineering operating model is intended to:

- align detection content to enterprise risk and attacker behavior
- define how detections are requested, developed, reviewed, and maintained
- establish clear roles and responsibilities
- improve the quality, consistency, and explainability of detections
- support a measurable and governed detection lifecycle
- connect detection engineering with SOC, IR, threat hunting, and leadership reporting

---

## Core Functions

### 1. Strategy and Prioritization
The program identifies and prioritizes detection opportunities based on:
- threat intelligence
- incident response findings
- purple team or red team exercises
- ATT&CK coverage gaps
- SOC analyst feedback
- mission or compliance requirements
- telemetry availability

### 2. Detection Content Development
Detection engineers build and maintain:
- analytic rules
- detection metadata
- ATT&CK mappings
- Cyber Kill Chain mappings
- triage guides
- validation notes
- rule documentation

### 3. Validation and Quality Assurance
Detection content should be reviewed for:
- query correctness
- metadata completeness
- mapping accuracy
- operational usefulness
- likely false positives
- alignment to repository standards

### 4. Governance and Lifecycle Management
Each detection moves through a controlled lifecycle:
- experimental
- testing
- production
- deprecated

Governance ensures detections have:
- ownership
- severity assignment
- validation notes
- triage guidance
- change history
- consistent naming and tagging

### 5. Deployment and Change Control
Detection content is managed through version control and reviewed before being promoted or deployed.

Deployment maturity may evolve from:
- manual deployment
- controlled peer-reviewed deployment
- CI/CD-assisted validation
- automated deployment workflows

### 6. Reporting and Continuous Improvement
The program tracks:
- detection count by lifecycle
- ATT&CK tactic and technique coverage
- content quality and completeness
- validation progress
- documentation maturity
- strategic gaps and roadmap priorities

---

## Operating Principles

### Threat-Informed
Detection engineering should prioritize meaningful attacker behaviors, not just raw event volume.

### Repeatable
Detections should be managed using documented standards, templates, and workflows.

### Measurable
Program value should be visible through coverage, quality, and maturity reporting.

### Explainable
Each detection should be understandable by analysts, engineers, and leadership stakeholders.

### Maintainable
Detections should be easy to review, tune, document, and retire when needed.

### Collaborative
Detection engineering should integrate feedback from SOC, IR, hunting, and leadership.

---

## Roles and Responsibilities

### Detection Engineering
Responsible for:
- detection design
- content authoring
- documentation
- mapping
- lifecycle management
- standards maintenance

### SOC Analysts
Responsible for:
- alert feedback
- false-positive identification
- operational usability feedback
- escalation quality observations

### Incident Response
Responsible for:
- identifying missed detections or improvement opportunities
- feeding lessons learned back into detection engineering
- helping prioritize high-value detection content

### Threat Hunting / Purple Team
Responsible for:
- generating new use cases
- validating attacker-behavior visibility
- helping test or simulate detection scenarios

### Leadership / Program Owners
Responsible for:
- prioritization support
- resource alignment
- maturity tracking
- executive oversight
- roadmap support

---

## Detection Flow

1. Detection opportunity identified
2. Intake and prioritization performed
3. Rule design and content development begins
4. Documentation and mappings added
5. Initial validation and QA performed
6. Rule promoted into lifecycle workflow
7. Triage and operational feedback collected
8. Reporting and improvement actions tracked

---

## Key Program Inputs

Examples of inputs into the operating model:
- ATT&CK coverage gaps
- alert fatigue trends
- incident postmortems
- threat intelligence reporting
- data source onboarding
- analyst observations
- compliance or mission requirements

---

## Key Outputs

Examples of outputs produced by the program:
- detections as code
- triage guides
- tracking matrices
- maturity reports
- ATT&CK coverage updates
- roadmap priorities
- governance updates
- validation evidence

---

## Success Measures

Examples of program success indicators:
- increased ATT&CK coverage
- reduced alert noise for mature detections
- more detections with triage guidance and ownership
- improved consistency in rule metadata
- better alignment between SOC findings and engineering updates
- measurable progress across lifecycle stages

---

## Repository Alignment

This repository supports the operating model by centralizing:
- strategy documents
- process documentation
- governance standards
- detection content
- coverage artifacts
- triage guides
- reporting materials
- future automation workflows

The repository is intended to serve as the primary knowledge and content management location for the detection engineering program.