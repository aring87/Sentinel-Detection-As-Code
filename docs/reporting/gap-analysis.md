# Detection Engineering Gap Analysis

## Purpose

This document captures known gaps in the detection engineering program so they can be tracked, prioritized, and addressed through roadmap planning and content development.

The goal is to make gaps visible and actionable rather than leaving them informal or implied.

---

## Gap Analysis Objectives

This analysis is intended to:

- identify missing or weak coverage areas
- distinguish between telemetry gaps and engineering gaps
- support roadmap prioritization
- improve ATT&CK alignment
- highlight documentation and governance weaknesses
- give leadership and engineers a shared view of what is still missing

---

## Gap Categories

Gaps should be reviewed across multiple dimensions.

### 1. Coverage Gaps
Areas where meaningful attacker behavior is not adequately addressed.

### 2. Telemetry Gaps
Areas where desired use cases are blocked by missing or insufficient data sources.

### 3. Documentation Gaps
Areas where detections or program artifacts lack supporting documentation.

### 4. Governance Gaps
Areas where standards, ownership, lifecycle discipline, or structure are incomplete.

### 5. Validation Gaps
Areas where detections exist but do not yet have meaningful validation support.

### 6. Reporting Gaps
Areas where metrics, maturity views, or leadership reporting remain incomplete.

### 7. Platform Expansion Gaps
Areas where the program is still too narrow or not yet ready for cross-platform maturity.

---

## Gap Review Method

Gap analysis should consider questions such as:

- which ATT&CK tactics have the weakest coverage?
- which critical use cases are missing?
- which detections lack owners or triage guides?
- which data sources are not yet onboarded or cataloged well enough?
- where are documentation standards incomplete?
- where does the program rely too heavily on manual effort?
- what prevents the next maturity level?

---

## Current Gap Areas

## 1. ATT&CK Coverage Gaps

### Example Observations
- some tactics may have starter detections but not yet mature coverage
- technique-level mapping may be incomplete
- content depth may be uneven across tactics
- some high-value enterprise behaviors may still be uncovered

### Suggested Actions
- review coverage matrix quarterly
- prioritize high-value gaps
- align future rule development to documented gaps

---

## 2. Detection Quality and Consistency Gaps

### Example Observations
- some detections may still need schema normalization
- rule metadata completeness may vary
- file naming and ID consistency may need continued review
- lifecycle assignments may not yet reflect true maturity

### Suggested Actions
- continue metadata normalization
- standardize IDs and lifecycle assignments
- use templates for all new content

---

## 3. Documentation Gaps

### Example Observations
- not all detections may have triage guides
- validation notes may be limited or absent
- some process documents may still be lightweight
- document indexes or navigation aids may still need improvement

### Suggested Actions
- expand triage guide coverage
- create validation support structure
- improve repository navigation

---

## 4. Telemetry and Data Source Gaps

### Example Observations
- some desired use cases may depend on telemetry not yet fully available
- not all use cases may map cleanly to current data sources
- field consistency may vary by table or source
- platform-specific constraints may affect rule portability

### Suggested Actions
- track missing telemetry dependencies
- expand the data source catalog over time
- align roadmap priorities to telemetry readiness

---

## 5. Operational Readiness Gaps

### Example Observations
- not all detections may be triage-ready
- ownership may not yet be assigned consistently
- validation maturity may be uneven
- production promotion criteria may need stronger enforcement

### Suggested Actions
- track readiness in the matrix
- expand ownership coverage
- define stronger lifecycle promotion expectations

---

## 6. Reporting and Metrics Gaps

### Example Observations
- metrics may be defined but not yet routinely measured
- quarterly review processes may still be forming
- some visuals may still be evolving
- executive summaries may need more regular cadence

### Suggested Actions
- define a regular reporting cadence
- create repeatable review workflows
- align visuals to leadership needs

---

## 7. Automation and Workflow Gaps

### Example Observations
- GitHub Actions may still be minimal
- metadata quality checks may not yet be enforced
- validation workflows may still be manual
- deployment support may still be early-stage

### Suggested Actions
- add schema validation checks
- add metadata completeness checks
- expand workflow automation over time

---

## 8. Multi-Platform Gaps

### Example Observations
- the repository currently centers on Sentinel
- broader detection engineering expansion is planned but not yet implemented
- Splunk structure may still be future-state

### Suggested Actions
- document cross-platform strategy
- prepare shared standards that can support future Splunk expansion
- keep platform-specific content organized but aligned

---

## Prioritization Guidance

Gaps should be prioritized based on:
- risk relevance
- mission impact
- telemetry feasibility
- operational value
- maturity impact
- engineering effort

Recommended priority labels:
- Critical
- High
- Medium
- Low

---

## Recommended Gap Tracking Format

Each tracked gap should include:
- gap title
- category
- description
- impact
- blocker or dependency
- suggested action
- owner if assigned
- priority
- status
- review date

---

## Example Gap Statements

### Example 1
**Gap:** Limited triage guide coverage for some tactic areas  
**Category:** Documentation Gap  
**Impact:** Reduces operational readiness for analysts  
**Priority:** High

### Example 2
**Gap:** Some ATT&CK mappings remain shallow or tactic-only  
**Category:** Coverage Gap  
**Impact:** Limits precision in coverage reporting  
**Priority:** Medium

### Example 3
**Gap:** Validation structure is not yet standardized across content  
**Category:** Validation Gap  
**Impact:** Slows maturity progression  
**Priority:** High

---

## Summary

A good gap analysis does not just list what is missing. It organizes the missing pieces into a roadmap-ready view that supports better prioritization, stronger reporting, and more deliberate program growth.