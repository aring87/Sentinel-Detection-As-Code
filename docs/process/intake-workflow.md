# Detection Intake Workflow

## Purpose

The intake workflow defines how new detection opportunities are identified, documented, and prioritized before engineering work begins.

The goal is to make sure detection requests are captured consistently and evaluated in a structured way rather than handled informally or lost over time.

---

## Intake Objectives

The intake process is intended to:

- capture detection opportunities in a repeatable format
- improve prioritization decisions
- connect requests to real use cases and telemetry
- reduce ad hoc or duplicate work
- provide traceability from request to content development
- support roadmap and coverage planning

---

## Common Intake Sources

Detection opportunities may originate from:

- incident response findings
- threat intelligence reporting
- purple team or red team exercises
- threat hunting discoveries
- SOC analyst observations
- ATT&CK gap reviews
- data source onboarding efforts
- leadership direction
- mission or compliance requirements

---

## Intake Questions

Each intake should answer basic questions such as:

- what behavior are we trying to detect?
- why does this matter?
- what threat or use case does it address?
- what data sources are available?
- what ATT&CK tactic or technique may apply?
- is this a new detection, enhancement, or gap?
- who requested it?
- what is the expected operational value?

---

## Minimum Intake Information

Each intake item should include:

- request title
- requestor
- date submitted
- problem statement
- threat or behavior description
- suggested data sources
- possible ATT&CK mapping
- priority or urgency
- related incident, hunt, or reference if applicable
- notes or supporting context

---

## Intake Workflow

## 1. Submit Request

### Description
A detection opportunity is documented using a standard intake format.

### Typical Mechanisms
- issue template
- markdown request file
- tracker row
- request form
- backlog item

### Output
A structured detection request exists.

---

## 2. Initial Review

### Description
The request is reviewed for completeness and basic feasibility.

### Review Questions
- is the use case understandable?
- is the request in scope?
- is enough context provided?
- is there likely supporting telemetry?
- is it clearly a detection need rather than another type of task?

### Output
The request is accepted for prioritization, sent back for clarification, or rejected as out of scope.

---

## 3. Prioritization

### Description
The request is evaluated against other work.

### Prioritization Factors
- threat relevance
- operational usefulness
- telemetry availability
- coverage gap impact
- mission relevance
- implementation effort
- potential analyst value
- stakeholder urgency

### Output
The request is categorized as high, medium, low, deferred, or backlog.

---

## 4. Triage and Classification

### Description
The request is classified into the appropriate type of work.

### Common Categories
- new detection
- enhancement to existing detection
- coverage gap
- documentation update
- triage guide need
- telemetry dependency
- future roadmap item

### Output
The request has a clearer path forward.

---

## 5. Assignment or Backlog Placement

### Description
The request is either assigned for development or placed into the appropriate backlog.

### Output
The request is visible in the program workflow and does not disappear into informal tracking.

---

## 6. Transition to Design

### Description
Approved requests move into the detection lifecycle design stage.

### Output
The intake item becomes an actionable engineering use case.

---

## Intake Decision Outcomes

Requests may result in one of the following outcomes:

### Approved
The request is accepted for development.

### Deferred
The request is valid but not yet prioritized.

### Needs Clarification
More information is required before prioritization.

### Out of Scope
The request does not belong in the detection engineering program.

### Telemetry Dependent
The request is valid but blocked by missing or insufficient data.

---

## Intake Governance Principles

The intake workflow should be:

### Structured
Requests should enter through a documented path.

### Visible
Requests should be traceable in a backlog, tracker, or issue workflow.

### Prioritized
Not all valid requests should be worked immediately.

### Explainable
Decisions should be understandable to stakeholders.

### Aligned
Requests should support program goals, coverage needs, and operational value.

---

## Recommended Repository Support

The intake workflow can be supported by:
- issue templates
- rule request template
- tracking matrix
- roadmap and gap analysis artifacts
- future backlog registers

---

## Summary

The intake workflow creates an orderly front door for detection engineering by turning raw ideas, incidents, and requests into structured, prioritized work that can be managed through the broader lifecycle.