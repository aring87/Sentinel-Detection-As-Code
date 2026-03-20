# Detection Engineering

A centralized repository for building, governing, validating, and reporting on a modern detection engineering program.

[![Executive Docs](https://img.shields.io/badge/Executive-Docs-blue)](docs/00_executive/)
[![Strategy](https://img.shields.io/badge/Strategy-Program-purple)](docs/01_strategy/)
[![Process](https://img.shields.io/badge/Process-Workflows-orange)](docs/02_process/)
[![Visuals](https://img.shields.io/badge/Visuals-Reports%20%26%20Diagrams-teal)](docs/03_visuals/)
[![Reporting](https://img.shields.io/badge/Reporting-Metrics%20%26%20Reviews-green)](docs/04_reporting/)
[![Detections](https://img.shields.io/badge/Detections-Sentinel-red)](detections/sentinel/)
[![Governance](https://img.shields.io/badge/Governance-Standards-darkgreen)](governance/)
[![Triage Guides](https://img.shields.io/badge/Triage-Guides-darkblue)](content/triage-guides/)

This repository serves as a one-stop location for:

- detection engineering strategy and program documentation
- executive proposal and maturity reporting
- detection-as-code content for Microsoft Sentinel
- governance, validation, tuning, and lifecycle standards
- ATT&CK and Cyber Kill Chain coverage tracking
- analyst triage guidance and operational support
- future multi-platform expansion, including Splunk

---

## Purpose

Detection engineering is more than writing alert logic. A mature program requires structure, governance, testing, reporting, and repeatable workflows that turn threat hypotheses into reliable, supportable analytics.

This repository is designed to support that full lifecycle.

---

## Start Here

### Leadership
Use these documents for program intent, operating model, roadmap, and reporting:

- [Executive Documents](docs/00_executive/)
- [Program Charter](docs/00_executive/program-charter.md)
- [Roadmap](docs/00_executive/roadmap.md)
- [Mission](docs/01_strategy/mission.md)
- [Scope](docs/01_strategy/scope.md)
- [Maturity Model](docs/01_strategy/maturity-model.md)
- [Metrics Catalog](docs/04_reporting/metrics-catalog.md)
- [Quarterly Program Review Template](docs/04_reporting/quarterly-program-review-template.md)
- [Annual Roadmap Review](docs/04_reporting/annual-roadmap-review.md)
- [Gap Analysis](docs/04_reporting/gap-analysis.md)

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
- [SOC and Incident Response Alignment](docs/02_process/soc-incident-response-alignment.md)
- [Alert Escalation Guidance](docs/02_process/alert-escalation-guidance.md)
- [Detection Feedback Loop](docs/02_process/detection-feedback-loop.md)
- [Coverage](coverage/)

---

## Repository Map

- `docs/` — executive artifacts, strategy, process, visuals, and reporting
- `detections/` — detection content managed as code
- `content/` — templates, triage guides, and reusable operational content
- `governance/` — naming, severity, lifecycle, tagging, and quality standards
- `coverage/` — ATT&CK and Cyber Kill Chain coverage tracking
- `automation/` — scripts, schemas, and deployment helpers
- `tests/` — validation support and testing references
- `.github/` — workflows, templates, and contribution support

---

## Executive Documents

Core program artifacts are located in [`docs/00_executive/`](docs/00_executive/):

- [Detection Engineering Proposal (DOCX)](docs/00_executive/detection-engineering-proposal.docx)
- [Detection Engineering Proposal (PDF)](docs/00_executive/detection-engineering-proposal.pdf)
- [Program Charter](docs/00_executive/program-charter.md)
- [Roadmap](docs/00_executive/roadmap.md)

---

## Current Focus

This repository is currently centered on **Microsoft Sentinel detection engineering** and is structured to mature into a broader, multi-platform detection engineering program over time.

Planned future growth includes:

- expanded automation and validation workflows
- stronger deployment and reporting pipelines
- additional platform support such as Splunk
- shared governance and reporting across security platforms

---

## Detection Lifecycle

Detection content should move through a controlled lifecycle:

- `experimental`
- `testing`
- `production`
- `deprecated`

See:

- [`docs/02_process/detection-lifecycle.md`](docs/02_process/detection-lifecycle.md)
- [`governance/lifecycle-standard.md`](governance/lifecycle-standard.md)

---

## Contribution Model

All content should be version controlled, reviewed, and validated before promotion.

Recommended flow:

1. Submit a request or change
2. Review metadata, mapping, and quality
3. Validate logic and operational usefulness
4. Document tuning or triage considerations
5. Merge through pull request review
6. Promote through lifecycle stages

See:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [Governance](governance/)
- [Documentation Hub](docs/)

---

## License

This repository is licensed under the MIT License. See [LICENSE](LICENSE).
