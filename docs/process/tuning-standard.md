# Tuning Standard

## Purpose

This standard defines how tuning should be approached within the detection engineering program.

The goal is to improve the clarity, usefulness, and maintainability of detection content by documenting how detections are refined over time as the program matures.

---

## Objectives

The tuning standard is intended to:

- provide a consistent approach for refining detections
- reduce unmanaged detection noise
- preserve visibility into why changes are made
- improve detection usefulness for analysts
- support lifecycle progression
- align tuning decisions to governance and change control

---

## What Tuning Means

Tuning is the process of refining a detection to improve its operational value without losing sight of the behavior it was originally intended to identify.

Tuning may include:
- narrowing overly broad logic
- documenting expected benign behavior
- improving context or metadata
- refining severity
- clarifying triage guidance
- improving rule structure and explainability
- managing known edge cases through documented adjustments

Tuning should not mean hiding meaningful risk without documentation or approval.

---

## Tuning Principles

Tuning should be:

### Intentional
Changes should be based on a clear reason, not informal preference alone.

### Documented
Adjustments should be reflected in repository history and supporting notes.

### Risk-Aware
Reducing noise should not come at the cost of removing meaningful visibility without review.

### Proportional
The level of tuning effort should match the importance and maturity of the detection.

### Governed
Significant tuning changes should align with change control and, where needed, exception management.

---

## Common Tuning Drivers

Tuning may be prompted by:
- repeated known benign behavior
- overly broad logic
- poor triage clarity
- low-value alerting behavior
- unclear severity alignment
- new understanding of the use case
- changes in telemetry or environment assumptions

---

## Common Tuning Areas

### 1. Logic Refinement
Adjusting logic structure so the rule more clearly aligns to the intended behavior.

### 2. Documentation Improvement
Updating false-positive notes, triage guidance, validation notes, or descriptive fields.

### 3. Severity Adjustment
Refining severity so it better reflects expected risk and operational importance.

### 4. Lifecycle Reassessment
Updating lifecycle state if the rule is more or less mature than originally recorded.

### 5. Context Enrichment
Improving the rule so it produces more useful supporting context for analysts.

---

## Tuning Decision Questions

Before making a tuning change, ask:

- what problem is being solved?
- does the change preserve the original detection objective?
- is the change documented clearly enough for later review?
- does the change affect severity, lifecycle, or mapping?
- does the change require exception tracking or additional review?

---

## Tuning Documentation Expectations

When a rule is tuned, consider updating:
- falsepositives
- triage guidance
- validation notes
- severity
- lifecycle
- notes in the tracking matrix
- supporting review comments or change description

---

## Tuning and Governance

Tuning should align with:
- change control
- exception management
- lifecycle management
- quality review expectations
- repository contribution workflow

This ensures tuning remains visible and does not become a silent source of drift or unmanaged suppression.

---

## Tuning Outcomes

Tuning changes may result in:
- better clarity
- improved maintainability
- stronger triage usefulness
- more accurate metadata
- better readiness for later validation
- better lifecycle alignment

---

## Tuning Cautions

Avoid tuning changes that:
- remove useful visibility without explanation
- create unclear exceptions
- weaken mapping accuracy
- obscure why the rule exists
- introduce silent assumptions not documented anywhere

---

## Recommended Repository Support

This standard is supported by:
- tracking matrix
- triage guides
- change control process
- exception management process
- contribution workflow
- future validation notes and evidence structures

---

## Summary

The tuning standard provides a structured and governed way to refine detection content over time so that changes improve clarity and maintainability while preserving the purpose and visibility of the original detection use case.