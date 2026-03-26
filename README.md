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

Core program artifacts are located in [`docs/executive/`](docs/executive/):

- [Detection Engineering Proposal (DOCX)](docs/executive/detection-engineering-proposal.docx)
- [Detection Engineering Proposal (PDF)](docs/executive/detection-engineering-proposal.pdf)
- [Program Charter](docs/executive/program-charter.md)
- [Roadmap](docs/executive/roadmap.md)

---

## Current Focus

This repository is currently centered on **Microsoft Sentinel detection engineering** and is structured to mature into a broader, multi-platform detection engineering program over time.

Planned future growth includes:

- expanded automation and validation workflows
- stronger deployment and reporting pipelines
- additional platform support such as Splunk
- shared governance and reporting across security platforms

---

## Detection Content Cleanup and Standardization

This repository recently underwent a broad cleanup and normalization effort across the Microsoft Sentinel detection catalog and supporting triage content.

### What was updated

- reviewed Sentinel detections across all major tactic folders for:
  - duplicate titles
  - duplicate IDs
  - overlapping or near-duplicate analytics
  - outdated schema formats
  - inconsistent metadata
  - weak or overly broad detection logic

- standardized detection content into a more consistent Sentinel-friendly schema, including fields such as:
  - `platform`
  - `query_language`
  - `severity`
  - `risk_score`
  - `data_sources`
  - `triage`
  - `validation`
  - `lifecycle`
  - `owner`
  - normalized `tags`

- corrected content quality issues such as:
  - duplicate rule IDs
  - conflicting `status` and `lifecycle` values
  - inconsistent ATT&CK mappings
  - unrealistic false positive sections
  - legacy or package-style YAML structures that did not match the repository standard

- improved detection quality by:
  - tightening noisy logic
  - improving KQL consistency
  - adding richer process, registry, file, and network context
  - refining multi-source correlation logic
  - separating broad foundational detections from narrower higher-fidelity companion analytics
  - retiring or replacing weaker legacy duplicates where stronger rules already existed

### Areas reviewed

The cleanup covered content across:

- `browser`
- `collection`
- `command-and-control`
- `credential-access`
- `defense-evasion`
- `discovery`
- `execution`
- `exfiltration`
- `impact`
- `initial-access`
- `lateral-movement`
- `persistence`
- `privilege-escalation`
- `reconnaissance`
- `resource-development`

### Key outcomes

- cleaner rule placement by tactic folder
- fewer duplicate and near-duplicate analytics
- more consistent metadata and schema structure
- improved ATT&CK alignment
- better analyst-facing triage guidance
- clearer distinction between:
  - foundational broad detections
  - higher-fidelity specialized detections
  - deprecated or legacy content

### Triage guide improvements

Related triage guides were also reviewed and rewritten into a more complete analyst-playbook format. Updated guides now better align with detection logic and include clearer investigation flow, escalation criteria, and response guidance.

### Current direction

The repository is continuing to mature toward a more governed detection engineering model with:

- stronger detection-as-code standards
- better lifecycle management
- improved quality control and validation
- more consistent triage support
- cleaner promotion from `experimental` to `testing` to `production`

---

## Detection Lifecycle

Detection content should move through a controlled lifecycle:

- `experimental`
- `testing`
- `production`
- `deprecated`

See:

- [`docs/02_process/detection-lifecycle.md`](docs/process/detection-lifecycle.md)
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
