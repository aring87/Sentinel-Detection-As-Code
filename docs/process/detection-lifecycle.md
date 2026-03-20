# Detection Lifecycle

## Purpose

The detection lifecycle defines how detection content moves from idea to sustained operational value.

Its purpose is to ensure detections are not created as one-time artifacts, but are instead developed, documented, reviewed, improved, and retired through a structured process.

---

## Lifecycle Objectives

The lifecycle is intended to:

- create a repeatable path for developing detections
- improve consistency in content quality
- support governance and documentation
- reduce unmanaged detection sprawl
- clarify when content is ready for broader operational use
- provide a controlled way to retire outdated or low-value content

---

## Lifecycle Stages

## 1. Intake

### Description
A detection opportunity is identified and recorded.

### Common Inputs
- threat intelligence
- incident response findings
- purple team or red team activity
- threat hunting discoveries
- ATT&CK coverage gaps
- SOC analyst feedback
- known platform or telemetry opportunities
- mission or compliance requirements

### Primary Outputs
- use case captured
- problem statement documented
- initial priority assessed
- data source needs identified

---

## 2. Design

### Description
The detection concept is translated into an initial design.

### Activities
- define the behavior to detect
- identify relevant data sources
- determine ATT&CK and CKC alignment
- consider likely false positives
- estimate expected fidelity
- define what good triage context should look like

### Primary Outputs
- initial use case logic
- draft metadata
- mapping assumptions
- detection approach documented

---

## 3. Build

### Description
The detection is created as a repository-managed content artifact.

### Activities
- author rule logic
- apply metadata schema
- assign lifecycle state
- document severity and ownership
- add supporting notes or template fields

### Primary Outputs
- draft detection content
- initial repository placement
- starter documentation

---

## 4. Review

### Description
The detection is reviewed for correctness, consistency, and completeness.

### Review Areas
- logic quality
- metadata completeness
- naming consistency
- ATT&CK mapping
- severity selection
- ownership
- repository placement
- triage usefulness

### Primary Outputs
- review comments
- required corrections
- improved content quality

---

## 5. Validate

### Description
The detection is assessed for usefulness and basic accuracy.

### Activities
- confirm query or logic runs successfully
- review expected behavior coverage
- assess whether the logic is understandable
- document assumptions and validation notes
- confirm the rule aligns with intended use case

### Primary Outputs
- validation notes
- readiness observations
- known gaps or open questions

---

## 6. Tune

### Description
The detection is refined to improve signal quality and reduce unnecessary noise.

### Activities
- document known benign patterns
- adjust thresholds or exclusions where justified
- improve triage context
- refine severity if needed
- capture known limitations

### Primary Outputs
- updated false-positive notes
- improved triage guidance
- clearer operational expectations

---

## 7. Promote

### Description
The detection advances through lifecycle states based on readiness.

### Standard Lifecycle States
- experimental
- testing
- production
- deprecated

### Promotion Considerations
- metadata completeness
- documentation quality
- operational usefulness
- review completion
- validation confidence
- ownership clarity

### Primary Outputs
- lifecycle update
- improved program visibility
- tracking matrix updates

---

## 8. Operate

### Description
The detection is maintained as an active part of the program.

### Activities
- maintain rule quality
- update supporting documentation
- capture operational feedback
- review for continued relevance
- align with evolving coverage needs

### Primary Outputs
- continued content maintenance
- updated ownership and notes
- operational improvement inputs

---

## 9. Retire or Replace

### Description
The detection is deprecated or replaced when it is no longer appropriate.

### Reasons for Retirement
- obsolete logic
- duplicate coverage
- telemetry changes
- low ongoing value
- better replacement detection exists
- content no longer fits program direction

### Primary Outputs
- deprecated lifecycle status
- documented replacement if applicable
- preserved historical traceability

---

## Lifecycle States

## Experimental
Early-stage content that is drafted and structured but not yet considered mature.

## Testing
Content that is under active review and refinement and is being evaluated for broader operational readiness.

## Production
Content that is sufficiently documented, governed, and supported for normal operational use.

## Deprecated
Content that is no longer recommended for active use and has been retired or replaced.

---

## Lifecycle Principles

The lifecycle should be:

### Structured
Each detection should follow a recognizable path.

### Visible
Lifecycle state should be clearly documented.

### Governed
Movement between states should reflect actual readiness, not just elapsed time.

### Maintainable
Detections should continue to be reviewed and improved after creation.

### Traceable
Changes, promotions, and retirements should be visible through repository history and program artifacts.

---

## Supporting Repository Artifacts

The lifecycle is supported by:
- tracking matrix
- triage guides
- governance standards
- change control process
- exception management process
- contribution workflow
- future validation evidence structures

---

## Summary

The detection lifecycle provides the operational path for detection content from initial idea to maintained program asset. It helps ensure detections are built deliberately, documented consistently, and improved over time rather than treated as one-off alerts.