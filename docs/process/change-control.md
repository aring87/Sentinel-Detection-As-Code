# Change Control

## Purpose

Change control defines how updates to detection content, documentation, governance, and reporting artifacts are proposed, reviewed, approved, and tracked.

The objective is to ensure that repository changes are deliberate, understandable, and auditable.

---

## Scope

This process applies to changes involving:
- detection rules
- mappings
- triage guides
- tracking matrices
- governance documents
- process documents
- reporting artifacts
- automation and validation workflows

---

## Change Control Objectives

The change control process is intended to:
- preserve content quality
- reduce accidental regressions
- improve review discipline
- maintain traceability
- support lifecycle governance
- protect production-bound content from unmanaged changes

---

## Change Types

### New Content
Examples:
- new detection rule
- new triage guide
- new governance document
- new workflow or automation file

### Content Update
Examples:
- query refinement
- ATT&CK mapping correction
- severity adjustment
- metadata update
- documentation improvement

### Tuning Change
Examples:
- threshold adjustment
- allowlist addition
- known benign suppression
- false-positive reduction update

### Structural Change
Examples:
- renaming folders
- moving files
- reorganizing repository layout
- changing naming conventions

### Deprecation or Removal
Examples:
- retiring obsolete rules
- removing duplicate content
- replacing old templates or guides

---

## Required Change Information

Each change should clearly document:
- what changed
- why the change was needed
- affected files or detections
- operational impact
- mapping impact if applicable
- validation or review notes
- lifecycle implications if applicable

---

## Review Expectations

### Documentation Changes
Should be reviewed for:
- clarity
- consistency
- alignment with repository standards

### Detection Changes
Should be reviewed for:
- query correctness
- required metadata
- ATT&CK mapping
- false-positive considerations
- triage usefulness
- lifecycle appropriateness

### High-Impact Changes
Examples:
- major query changes
- severity changes
- production promotion
- broad suppressions or exclusions

Should receive closer peer review and may require leadership or senior engineering review.

---

## Approval Guidance

Suggested approval model:

- documentation-only changes: 1 reviewer
- detection content updates: 1–2 reviewers
- production-impacting logic changes: 2 reviewers when possible
- major structural or governance changes: designated repo owner or program lead

---

## Change Workflow

1. identify change need
2. update content in repository
3. review affected files
4. validate quality and completeness
5. document impact
6. submit through pull request or tracked review path
7. approve and merge
8. update lifecycle or reporting artifacts if needed

---

## Emergency Changes

In rare cases, urgent changes may need faster review.

Examples:
- noisy detection overwhelming operations
- major error in production logic
- broken query affecting critical alerting

Emergency changes should still be:
- documented
- reviewed as soon as possible afterward
- clearly marked in commit history or change notes

---

## Traceability

All meaningful changes should be traceable through:
- commit history
- pull requests
- issue references
- change notes
- tracker updates

Traceability is especially important for:
- severity changes
- lifecycle promotions
- suppressions or allowlists
- rule removals
- naming standard changes

---

## Promotion Considerations

Changes that support moving a rule from one lifecycle stage to another should include:
- validation notes
- documentation completeness
- triage readiness
- review confirmation
- updated tracking matrix status

---

## Repository Controls

The repository should support change control through:
- branch-based workflow
- pull request templates
- issue templates
- contribution guidance
- review expectations
- commit history

---

## Success Criteria

A healthy change control process should result in:
- fewer unmanaged edits
- more consistent detection quality
- clearer ownership
- better auditability
- safer promotion of content through lifecycle stages