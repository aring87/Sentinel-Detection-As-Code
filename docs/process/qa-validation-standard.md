# QA and Validation Standard

## Purpose

This standard defines the minimum expectations for reviewing and validating detection content before it is considered more mature within the program.

The goal is to improve consistency, quality, and explainability while ensuring detections are understandable and maintainable as engineering artifacts.

---

## Objectives

The QA and validation standard is intended to:

- improve content consistency
- reduce avoidable quality issues
- support lifecycle progression
- ensure metadata and documentation expectations are met
- create confidence that a detection aligns with its stated purpose
- make detections easier to review, maintain, and report on

---

## Scope

This standard applies to:
- new detections
- updated detections
- detection metadata changes
- triage-supporting content where applicable
- lifecycle promotions when readiness is being assessed

---

## QA Principles

Quality assurance should be:

### Consistent
The same basic expectations should apply across all detection content.

### Traceable
Review observations should be reflected in repository history, comments, or supporting notes.

### Practical
The process should improve content quality without becoming so heavy that it blocks all progress.

### Scalable
The standard should work for both early-stage and more mature content.

### Explainable
The quality of a rule should be understandable to engineers and stakeholders.

---

## Minimum QA Review Areas

Each detection should be reviewed for the following areas.

## 1. Metadata Completeness

Confirm that the detection includes expected fields such as:
- title
- id
- description
- author
- date or modified date
- severity
- lifecycle
- owner where applicable
- tactics and techniques
- data sources
- tags

### Goal
Ensure the rule is governable and reportable.

---

## 2. Naming and Structure

Confirm that:
- file naming aligns with repository standards
- IDs follow the expected format
- folder placement is correct
- schema structure is consistent with current templates

### Goal
Ensure the content is organized and predictable.

---

## 3. Logic Quality

Confirm that:
- the logic reflects the stated behavior or use case
- the detection is understandable
- obvious syntax or structural issues are absent
- the rule meaning is not contradicted by its description or tags

### Goal
Ensure the detection concept is coherent and implementable.

---

## 4. Mapping Quality

Confirm that:
- ATT&CK tactic and technique mappings are reasonable
- Cyber Kill Chain tags or phases are appropriate when used
- mapping is not obviously over-broad or unrelated

### Goal
Ensure reporting and coverage artifacts remain meaningful.

---

## 5. Severity and Lifecycle Alignment

Confirm that:
- severity matches the apparent level of concern
- lifecycle status reflects actual readiness
- experimental content is not presented as if fully mature
- production designations are justified

### Goal
Ensure operational expectations are realistic.

---

## 6. Documentation Quality

Confirm that:
- description is clear
- false positives are noted when possible
- triage notes are usable
- validation notes are present or planned
- ownership is clear where applicable

### Goal
Ensure the rule is understandable beyond raw logic alone.

---

## Validation Expectations

Validation does not need to imply full production certification. At a minimum, validation should answer:

- does the rule align to the intended use case?
- is the logic understandable and reviewable?
- are the expected data sources identified?
- are important assumptions documented?
- are obvious operational questions addressed?

As the program matures, validation can expand to include:
- sample evidence
- test datasets
- expected results
- known benign cases
- structured review notes

---

## QA Outcomes

A QA review may result in:

### Accept
The content is acceptable at its current lifecycle stage.

### Accept with Minor Updates
The content is usable but should receive small improvements.

### Rework Required
The content has issues that should be addressed before progressing.

### Defer
The content may be valid, but depends on unresolved questions, telemetry, or program priorities.

---

## Promotion Readiness Considerations

Before moving content to a more mature lifecycle state, review whether it has:

- required metadata
- understandable logic
- appropriate mappings
- useful documentation
- ownership visibility
- sufficient review confidence for the target lifecycle

---

## Recommended Repository Support

This standard can be supported by:
- validation checklist template
- tracking matrix
- contribution guide
- pull request template
- future quality gates in GitHub Actions

---

## Summary

The QA and validation standard establishes a practical baseline for reviewing detection content so the program can improve consistency, maintainability, and confidence without relying on informal quality judgments alone.