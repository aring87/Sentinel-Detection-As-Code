# Detection Engineering Maturity Model

## Purpose

This maturity model provides a structured way to measure the development of the Detection Engineering Program over time.

It is intended to help the organization understand the current state of the program, identify gaps, and define the next steps required to mature detection engineering into a governed, measurable, and scalable capability.

---

## Maturity Model Goals

The maturity model is designed to:

- provide a common language for program progress
- clarify what “mature” detection engineering looks like
- support roadmap planning
- identify capability gaps
- align leadership expectations with realistic growth stages
- measure progress beyond simple rule counts

---

## Maturity Levels

## Level 1 — Ad Hoc

### Characteristics
- detections are created reactively
- little or no formal documentation exists
- detections may live in scattered locations
- metadata is inconsistent or incomplete
- coverage is not tracked
- ownership is unclear
- there is little lifecycle discipline

### Indicators
- rules are created case by case
- minimal governance exists
- no standard templates are used
- reporting is limited or absent

### Risks
- inconsistent quality
- duplicated effort
- poor maintainability
- weak visibility into actual coverage

---

## Level 2 — Emerging

### Characteristics
- a shared repository begins to exist
- basic templates and folder structures are introduced
- some ATT&CK mapping is applied
- documentation begins, but is incomplete
- lifecycle concepts are introduced informally
- rule creation becomes more repeatable

### Indicators
- detections are increasingly managed as code
- initial standards are defined
- some process documentation exists
- basic coverage tracking begins

### Risks
- inconsistency remains high
- rule quality varies significantly
- triage and validation practices are still immature

---

## Level 3 — Defined

### Characteristics
- program strategy and operating model are documented
- detections follow a consistent schema
- naming, severity, tagging, and lifecycle standards exist
- coverage is tracked in a structured way
- triage guides and tracking matrices are maintained
- content is reviewed using documented expectations

### Indicators
- governance is visible in the repository
- process documentation exists for intake, change control, and exceptions
- metadata quality is improving
- leadership-facing documents are established

### Risks
- validation may still be inconsistent
- automation may still be limited
- maturity may depend heavily on manual effort

---

## Level 4 — Managed

### Characteristics
- content quality is measured using repeatable metrics
- validation practices are more structured
- lifecycle promotion is based on clearer readiness criteria
- change control is consistently applied
- reporting is performed on a regular cadence
- exceptions are tracked and reviewed
- detection content is easier to maintain and audit

### Indicators
- measurable quality and maturity metrics exist
- triage-ready content is increasing
- documentation completeness is tracked
- leadership reporting becomes more consistent

### Risks
- scaling challenges may remain without automation
- quality may still depend on individual effort if workflows are not enforced

---

## Level 5 — Optimized

### Characteristics
- detection engineering is fully treated as an engineering program
- validation, reporting, and review workflows are mature and repeatable
- automation supports quality checks and deployment readiness
- content decisions are informed by metrics, gaps, and operational feedback
- the program is scalable across tactics, data sources, and platforms
- leadership visibility is strong and sustained

### Indicators
- automation assists validation and policy enforcement
- roadmap progress is measurable
- coverage management is deliberate and data-informed
- cross-platform detection engineering can be supported
- continuous improvement is built into the operating rhythm

### Risks
- fewer structural risks remain, but success depends on continued governance and adaptation

---

## Maturity Dimensions

Program maturity should be assessed across several dimensions, not just total rule count.

### 1. Strategy
Is the program supported by clear mission, scope, roadmap, and operating model documents?

### 2. Governance
Are naming, lifecycle, severity, tagging, and quality standards defined and followed?

### 3. Content Quality
Do detections have consistent metadata, ownership, and documentation?

### 4. Coverage Management
Is ATT&CK coverage tracked and are gaps documented and prioritized?

### 5. Operational Readiness
Do detections include triage guidance, lifecycle status, and usable documentation?

### 6. Validation
Are there structured expectations for testing, false-positive review, and content review?

### 7. Reporting
Are metrics, maturity, and progress communicated regularly to stakeholders?

### 8. Automation
Are validation, quality checking, and future deployment workflows supported by automation?

---

## Current-State Assessment Guidance

To assess the program, ask questions such as:

- Is the repository structured and governed?
- Are detections consistently documented?
- Is there a clear lifecycle model?
- Are coverage gaps tracked?
- Are triage guides available for priority detections?
- Are reporting artifacts maintained?
- Is maturity improving across documentation, governance, and content?

---

## How to Use This Model

This maturity model should be used to:

- identify the current maturity level
- define near-term priorities
- support roadmap planning
- communicate progress to leadership
- guide future investments in validation and automation

The goal is not to jump to the highest level quickly, but to mature deliberately with a strong foundation.

---

## Summary

A mature detection engineering capability is not defined only by how many detections exist. It is defined by how well those detections are governed, documented, measured, maintained, and improved over time.