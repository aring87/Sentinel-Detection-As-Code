# Detection Engineering Metrics Catalog

## Purpose

This catalog defines the key metrics used to understand the health, maturity, quality, and growth of the detection engineering program.

The goal is not just to count detections, but to measure how well the program is structured, governed, and progressing over time.

---

## Metrics Design Principles

Program metrics should be:
- understandable
- relevant to stakeholders
- useful for decision-making
- aligned to program maturity
- reviewed periodically
- balanced between quantity and quality

---

## Metric Categories

### 1. Inventory Metrics
Used to understand how much content exists.

### 2. Lifecycle Metrics
Used to understand the maturity of content.

### 3. Coverage Metrics
Used to understand how well detections map to targeted attacker behavior.

### 4. Quality Metrics
Used to assess documentation and metadata completeness.

### 5. Operational Readiness Metrics
Used to assess whether detections are supported by triage and ownership.

### 6. Program Maturity Metrics
Used to measure program development over time.

---

## Core Metrics

### Total Detections
**Definition:**  
Total number of detections maintained in the repository.

**Why It Matters:**  
Provides a basic inventory view of program content.

---

### Detections by Lifecycle
**Definition:**  
Number of detections in:
- experimental
- testing
- production
- deprecated

**Why It Matters:**  
Shows maturity distribution and promotion progress.

---

### Detections by ATT&CK Tactic
**Definition:**  
Count of detections mapped to each ATT&CK tactic.

**Why It Matters:**  
Shows where engineering effort is concentrated and where gaps remain.

---

### Detections by Data Source
**Definition:**  
Count of detections supported by each major telemetry source.

**Why It Matters:**  
Shows telemetry dependence and helps identify high-value onboarding needs.

---

### Detections with Owners Assigned
**Definition:**  
Percentage of detections that include a documented owner.

**Why It Matters:**  
Improves accountability and long-term maintainability.

---

### Detections with Triage Guides
**Definition:**  
Percentage of detections with linked or associated triage guidance.

**Why It Matters:**  
Indicates analyst readiness and operational support maturity.

---

### Detections with Validation Notes
**Definition:**  
Percentage of detections with documented validation content or references.

**Why It Matters:**  
Shows progress toward quality assurance and repeatability.

---

### Detections with Complete Metadata
**Definition:**  
Percentage of detections that meet the repository metadata standard.

**Why It Matters:**  
Measures content consistency and governance adherence.

---

### Coverage Gaps Identified
**Definition:**  
Number of ATT&CK techniques or priority use cases documented as gaps.

**Why It Matters:**  
Improves roadmap visibility and prioritization.

---

### Coverage Gaps Closed
**Definition:**  
Number of documented gaps addressed during a defined period.

**Why It Matters:**  
Shows measurable progress in coverage expansion.

---

### Triage-Ready Detections
**Definition:**  
Number or percentage of detections with usable triage guidance, ownership, and severity.

**Why It Matters:**  
Reflects whether detections are operationally consumable.

---

### Detection Content Added Per Period
**Definition:**  
Number of new detections added during a month or quarter.

**Why It Matters:**  
Shows content growth, but should always be interpreted alongside quality metrics.

---

### Detection Content Updated Per Period
**Definition:**  
Number of existing detections revised during a month or quarter.

**Why It Matters:**  
Shows whether the program is maintaining and improving content, not just adding more.

---

### Documentation Coverage Rate
**Definition:**  
Percentage of core program artifacts completed and maintained.

Examples:
- charter
- roadmap
- lifecycle docs
- governance standards
- triage templates
- tracking matrix

**Why It Matters:**  
Shows whether the program foundation is maturing alongside detection volume.

---

## Suggested Reporting Views

### Executive View
Focus on:
- total detections
- detections by lifecycle
- ATT&CK coverage trend
- gap closure trend
- program maturity milestones

### Operational View
Focus on:
- triage-ready detections
- detections with owners
- detections with validation notes
- detections updated during the period

### Engineering View
Focus on:
- metadata completeness
- mappings coverage
- data source distribution
- lifecycle progression
- backlog of content to standardize

---

## Reporting Cadence

Suggested review cadence:
- monthly for engineering and operational metrics
- quarterly for leadership and roadmap reporting
- annual for maturity review and strategic planning

---

## Metric Interpretation Guidance

Metrics should be interpreted carefully.

Examples:
- a high total rule count does not automatically mean strong coverage
- a low production count may be acceptable in an early-stage program
- more detections are not always better if documentation quality is poor
- lifecycle, coverage, and quality metrics should be read together

---

## Future Expansion

Over time, the catalog may expand to include:
- time-to-publish metrics
- validation completion rates
- exception counts
- data source onboarding metrics
- rule review backlog
- percentage of detections linked to incidents or hunts
- automation adoption metrics

---

## Summary

A healthy detection engineering metrics program should help answer:
- what content exists
- how mature it is
- how well it is documented
- where gaps remain
- how the program is improving over time