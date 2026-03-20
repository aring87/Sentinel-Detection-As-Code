# SOC and Incident Response Alignment

## Purpose

This document defines how the detection engineering program aligns with SOC operations and incident response functions.

The goal is to ensure detections are not developed in isolation, but instead support the workflows, needs, and lessons learned of the teams who use them operationally.

---

## Why Alignment Matters

Detection engineering creates the content, but SOC analysts and incident responders experience the operational reality of that content.

Alignment is important because:
- SOC analysts provide alert usability feedback
- incident responders identify missed detection opportunities
- both teams help validate whether detections are meaningful in practice
- operational experience improves prioritization and future engineering work

---

## Core Alignment Principles

### Shared Outcome
Detection engineering, SOC, and IR all support the same broader objective: identifying and responding to meaningful security activity more effectively.

### Usability Matters
A detection is more valuable when analysts can understand and investigate it quickly.

### Feedback Should Be Structured
Feedback from SOC and IR should be captured in a repeatable way, not left informal or lost over time.

### Engineering Should Be Operationally Informed
Detection content should reflect real investigative needs, not just theoretical logic.

---

## SOC Responsibilities

SOC teams help the program by:
- identifying noisy or unclear detections
- reporting investigation friction
- highlighting useful enrichment needs
- identifying missing triage guidance
- surfacing recurring alert patterns

---

## Incident Response Responsibilities

Incident response helps the program by:
- identifying missed detection opportunities
- contributing post-incident lessons learned
- highlighting attacker tradecraft that should inform future content
- helping prioritize high-value use cases
- identifying where current detections failed or lacked context

---

## Detection Engineering Responsibilities

Detection engineering supports SOC and IR by:
- creating governed and maintainable detections
- improving metadata and triage readiness
- documenting logic and intended behavior
- incorporating structured feedback
- translating lessons learned into updated or new content

---

## Alignment Inputs

Common inputs from SOC and IR include:
- false-positive observations
- missing context in alerts
- difficult-to-triage detections
- post-incident detection gaps
- suggestions for enrichment or better documentation
- recurring behavior patterns worth codifying

---

## Alignment Outputs

The alignment process should result in:
- improved triage guides
- better documentation
- more targeted roadmap priorities
- improved tracking of operational readiness
- better lifecycle decisions
- stronger content quality over time

---

## Recommended Working Model

A practical working model includes:
1. detections created in repository
2. triage guides provided for priority detections
3. SOC feedback captured in structured form
4. IR lessons reviewed after incidents
5. detection engineering updates content, matrix, or roadmap
6. program reporting reflects meaningful improvements

---

## Supporting Artifacts

This alignment is supported by:
- triage guides
- tracking matrix
- change control
- exception management
- quarterly reviews
- annual roadmap review
- gap analysis

---

## Summary

SOC and IR alignment ensures the detection engineering program remains operationally grounded, continuously improved, and focused on the real-world value of the content it produces.
