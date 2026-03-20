# Detection Feedback Loop

## Purpose

This document defines the feedback loop between detection engineering, SOC operations, and incident response.

The goal is to ensure detections improve over time based on real usage, real investigations, and real program gaps.

---

## Why the Feedback Loop Matters

Detection content should not be considered complete once it is written.

Feedback is needed because:
- analysts experience whether detections are understandable
- investigators discover where detections helped or failed
- recurring false positives reveal documentation or logic gaps
- incidents expose missing use cases and roadmap priorities

---

## Feedback Sources

Feedback may come from:
- SOC alert triage
- incident response investigations
- threat hunts
- purple team or red team exercises
- quarterly reporting review
- gap analysis
- content review cycles

---

## Common Feedback Types

Examples include:
- rule is noisy
- rule lacks enough triage context
- severity feels too high or too low
- ATT&CK mapping needs improvement
- a new triage guide is needed
- a new rule is needed
- an existing rule is obsolete
- ownership or lifecycle needs updating

---

## Feedback Workflow

## 1. Feedback Identified
A useful observation is made by SOC, IR, hunting, or engineering.

## 2. Feedback Captured
The observation is documented in a consistent location such as:
- issue
- tracker note
- matrix note
- review log
- future backlog item

## 3. Feedback Classified
The observation is classified into categories such as:
- detection update
- documentation update
- triage guide improvement
- severity or lifecycle review
- roadmap gap
- telemetry dependency

## 4. Action Determined
The feedback is:
- acted on immediately
- queued for future work
- documented for later review
- rejected if out of scope or unsupported

## 5. Repository Updated
If action is taken, the corresponding detection, triage guide, tracking matrix, or roadmap artifact is updated.

## 6. Program Visibility Maintained
Important changes should be visible through:
- git history
- tracking matrix
- reporting artifacts
- roadmap updates
- quarterly review summaries

---

## Feedback Principles

### Make It Visible
Important feedback should be captured in a place that can be reviewed later.

### Keep It Actionable
Feedback should describe a real issue, gap, or improvement need.

### Tie It to Program Artifacts
Where possible, feedback should map to a rule, guide, process doc, gap, or roadmap item.

### Use It to Improve Maturity
The goal of feedback is not only to fix noise, but to improve quality, readiness, and structure over time.

---

## Outputs of the Feedback Loop

A healthy feedback loop should produce:
- stronger detections
- clearer triage guides
- better severity and lifecycle alignment
- more accurate reporting
- better roadmap priorities
- more honest gap visibility

---

## Summary

The detection feedback loop turns operational experience into program improvement. It is one of the most important mechanisms for maturing detection engineering from static content management into a continuously improving capability.
