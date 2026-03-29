# Content

This directory contains reusable supporting content for the detection engineering program.

It is intended to hold the operational material that makes detection content more usable, consistent, and maintainable across the full detection lifecycle. While the `detections/` directory contains the detection logic itself, this directory contains the templates, triage content, and supporting materials that help analysts, engineers, and responders work from the same standards.

## Sections

### Templates
- [Templates Folder](templates/)

Includes reusable content such as:
- detection rule templates
- rule request templates
- triage guide templates
- validation checklists
- workbook-related templates or supporting content where applicable

### Triage Guides
- [Triage Guides Folder](triage-guides/)
- [Priority Starter Rules](triage-guides/priority-starter-rules/)

These guides help analysts and responders understand:
- what a detection is looking for
- why the alert matters
- how to investigate it
- what benign explanations to consider
- when to escalate
- what response actions may be appropriate

### Runbooks
- [Runbooks Folder](runbooks/)

Reserved for analyst and engineering operating procedures, including repeatable investigation, tuning, and content-management workflows.

### Playbooks
- [Playbooks Folder](playbooks/)

Reserved for automation, orchestration, and response workflow content tied to detections, investigations, and operational response actions.

### Workbooks
- [Workbooks Folder](workbooks/)

Reserved for workbook-related content, supporting files, standards, and documentation used to support visualizations, analyst workflows, and reporting.

## Purpose

This directory supports repeatable detection engineering by providing the reusable content needed to:

- create detections consistently
- document triage guidance clearly
- support validation and review workflows
- improve operational usability for analysts and responders
- standardize supporting content across the repository

## Recommended Starting Points

- [Detection Rule Template](templates/detection-rule-template.yml)
- [Rule Request Template](templates/rule-request-template.md)
- [Triage Guide Template](templates/triage-guide-template.md)
- [Validation Checklist](templates/validation-checklist.md)

## Related Areas

- [Detections](../detections/)
- [Governance](../governance/)
- [Process Docs](../docs/02_process/)