# Detection Engineering

A centralized repository for building, governing, validating, and operationalizing a modern detection engineering program.

[![Executive Docs](https://img.shields.io/badge/Executive-Docs-blue)](docs/00_executive/)
[![Strategy](https://img.shields.io/badge/Strategy-Program-purple)](docs/01_strategy/)
[![Process](https://img.shields.io/badge/Process-Workflows-orange)](docs/02_process/)
[![Visuals](https://img.shields.io/badge/Visuals-Reports%20%26%20Diagrams-teal)](docs/03_visuals/)
[![Reporting](https://img.shields.io/badge/Reporting-Metrics%20%26%20Reviews-green)](docs/04_reporting/)
[![Detections](https://img.shields.io/badge/Detections-Sentinel%20%26%20Splunk-red)](detections/)
[![Governance](https://img.shields.io/badge/Governance-Standards-darkgreen)](governance/)
[![Triage Guides](https://img.shields.io/badge/Triage-Guides-darkblue)](content/triage-guides/)

This repository serves as a central hub for:

- detection engineering strategy and program documentation
- detection-as-code content for Microsoft Sentinel and Splunk
- validation, tuning, lifecycle governance, and quality control
- ATT&CK and Cyber Kill Chain coverage tracking
- analyst triage guidance and operational support
- executive reporting, planning, and program maturity development
- multi-platform detection engineering workflows

---

## Purpose

Detection engineering is more than writing alert logic.

A mature program requires structure, repeatable workflows, validation standards, triage guidance, operational feedback loops, and reporting that connects technical work to measurable outcomes. This repository is designed to support that full lifecycle, from detection idea to validated analytic to operational use.

---

## Current Focus

This repository is centered on building a more governed, scalable, and operationally useful detection engineering program across **Microsoft Sentinel** and **Splunk**.

Current priorities include:

- improving detection quality and consistency
- standardizing rule schema and metadata
- reducing duplicate and overlapping analytics
- strengthening analyst triage guidance
- improving ATT&CK alignment and lifecycle discipline
- expanding validation and automation workflows
- improving long-term maintainability across platforms

Planned future growth includes:

- stronger packaging and deployment workflows
- expanded reporting and quality metrics
- more mature CI/CD validation gates
- continued Splunk tuning for production-ready content
- shared governance across additional detection platforms

---

## What This Repository Contains

### Detection Content
Detection content is managed as code and currently organized under:

- `detections/sentinel/`
- `detections/splunk/`

Content is grouped by tactic and lifecycle state to support maintainability, validation, and operational alignment.

Current tactic areas include:

- browser
- collection
- command-and-control
- credential-access
- defense-evasion
- discovery
- execution
- exfiltration
- impact
- initial-access
- lateral-movement
- persistence
- privilege-escalation
- reconnaissance
- resource-development
- deprecated

### Triage Guides
Analyst-facing triage content is maintained under `content/triage-guides/` and is intended to support consistent investigation, escalation, and response.

### Governance
Governance content defines the standards used to maintain quality and consistency across the repository, including naming, severity, lifecycle, tagging, metadata, and rule quality expectations.

### Program Documentation
The `docs/` structure supports executive communication, strategy, process, reporting, and visual program artifacts.

### Validation and CI/CD
This repository includes validation workflows and practice CI/CD support for detection content. Platform-specific validation scripts are used to check Sentinel and Splunk detections for schema consistency, duplicate metadata, required fields, and active vs deprecated rule handling.

Current validation components include:

- `tests/validation/validate_detections.py`
- `tests/validation/validate_splunk_detections.py`

This helps support a Detection-as-Code workflow in which content can be validated before packaging or promotion.

---

## Start Here

### Leadership
Use these documents for program intent, operating model, roadmap, and reporting:

- [Executive Documents](docs/executive/)
- [Program Charter](docs/executive/program-charter.md)
- [Roadmap](docs/executive/roadmap.md)
- [Mission](docs/strategy/mission.md)
- [Scope](docs/strategy/scope.md)
- [Maturity Model](docs/strategy/maturity-model.md)
- [Metrics Catalog](docs/reporting/metrics-catalog.md)
- [Quarterly Program Review Template](docs/reporting/quarterly-program-review-template.md)
- [Annual Roadmap Review](docs/reporting/annual-roadmap-review.md)
- [Gap Analysis](docs/reporting/gap-analysis.md)

### Detection Engineers
Use these resources to build, review, validate, and maintain detection content:

- [Detections](detections/)
- [Governance](governance/)
- [Documentation Hub](docs/)
- [Detection Lifecycle](docs/02_process/detection-lifecycle.md)
- [QA and Validation Standard](docs/02_process/qa-validation-standard.md)
- [Tuning Standard](docs/02_process/tuning-standard.md)
- [Detection Rule Template](content/templates/detection-rule-template.yml)
- [Validation Checklist](content/templates/validation-checklist.md)

### SOC / Incident Response
Use these resources for investigation, escalation, and operational alignment:

- [Triage Guides](content/triage-guides/)
- [SOC and Incident Response Alignment](docs/process/soc-incident-response-alignment.md)
- [Alert Escalation Guidance](docs/process/alert-escalation-guidance.md)
- [Detection Feedback Loop](docs/process/detection-feedback-loop.md)
- [Coverage](coverage/)

---

## Detection Content Cleanup and Standardization

The detection catalog has undergone a broad cleanup and normalization effort to improve quality, consistency, and maintainability across both active and legacy content.

This work included:

- reviewing rules for duplicate titles and duplicate IDs
- identifying overlapping or near-duplicate analytics
- cleaning up inconsistent metadata and ATT&CK mappings
- improving weak or overly broad logic
- converting older or package-style rules into a more consistent repository schema
- aligning detections with stronger triage guidance
- separating broad foundational analytics from narrower companion detections
- retaining stronger modern rules while retiring or demoting weaker legacy duplicates

This effort covered content across major tactic folders and now supports both Sentinel and Splunk detection tracks.

### Resulting Improvements

Key outcomes of this cleanup include:

- cleaner rule placement by tactic
- fewer duplicate and near-duplicate detections
- more consistent schema and metadata
- improved ATT&CK alignment
- stronger triage and validation sections
- clearer lifecycle progression from experimental to production
- better separation between active, specialized, and deprecated content
- improved cross-platform consistency between Sentinel and Splunk content

---

## Triage Guide Improvements

Triage content has also been reviewed and expanded to better support analyst workflows.

Updated guides are being rewritten into a more complete analyst-playbook style that emphasizes:

- why the alert matters
- what the detection is looking for
- initial triage questions
- key fields to review
- step-by-step investigation guidance
- common benign explanations
- escalation criteria
- response actions
- analyst notes

This is intended to improve operational consistency and make the repository more useful to analysts, responders, and detection engineers alike.

---

## Detection Lifecycle

Detection content should move through a controlled lifecycle:

- `experimental`
- `testing`
- `production`
- `deprecated`

Lifecycle progression should reflect validation quality, operational usefulness, tuning maturity, and analyst confidence.

See:

- [Detection Lifecycle](docs/02_process/detection-lifecycle.md)
- [Lifecycle Standard](governance/lifecycle-standard.md)

---

## Detection-as-Code and Validation

This repository now reflects a more practical Detection-as-Code workflow.

Validation logic has been added for both Sentinel and Splunk content so detections can be checked before promotion. Current validation covers:

- required schema fields
- valid metadata values
- duplicate rule IDs
- duplicate rule titles
- active vs deprecated rule handling
- metadata quality issues such as incomplete or inconsistent fields

Current validation status:

- Sentinel detections validate successfully
- Splunk detections validate successfully

This provides a stronger foundation for future packaging, promotion, and deployment workflows.

---

## Repository Map

- `docs/` — executive artifacts, strategy, process, visuals, and reporting
- `detections/` — Sentinel and Splunk detection content managed as code
- `content/` — templates, triage guides, and reusable operational content
- `governance/` — naming, severity, lifecycle, tagging, and quality standards
- `coverage/` — ATT&CK and Cyber Kill Chain coverage tracking
- `automation/` — scripts, schemas, and deployment helpers
- `tests/` — validation support and testing references
- `.github/` — workflows, templates, and contribution support

---

## Executive Documents

Core program artifacts are located in [`docs/executive/`](docs/executive/):

- [Detection Engineering Proposal (DOCX)](docs/executive/detection-engineering-proposal.docx)
- [Detection Engineering Proposal (PDF)](docs/executive/detection-engineering-proposal.pdf)
- [Program Charter](docs/executive/program-charter.md)
- [Roadmap](docs/executive/roadmap.md)

---

## Contribution Model

All content should be version controlled, reviewed, validated, and governed before promotion.

Recommended flow:

1. Submit a request or change
2. Review metadata, mapping, and content quality
3. Validate logic and operational usefulness
4. Document tuning or triage considerations
5. Merge through pull request review
6. Promote through lifecycle stages

See:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [Governance](governance/)
- [Documentation Hub](docs/)

---

## Long-Term Direction

The long-term goal of this repository is to support a mature, scalable detection engineering program with:

- governed detection-as-code workflows
- operationally useful triage content
- measurable coverage tracking
- stronger validation and tuning discipline
- multi-platform detection support
- executive-ready reporting
- reusable standards that can extend across security platforms

---

## License

This repository is licensed under the MIT License. See [LICENSE](LICENSE).
