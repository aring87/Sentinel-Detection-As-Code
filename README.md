# 🛡️ Sentinel Detection-as-Code Repository

This repository contains a structured and lifecycle-driven collection of Microsoft Sentinel detection rules aligned to the MITRE ATT&CK framework and Cyber Kill Chain (CKC) phases.

## 📁 Repository Structure

```
Sentinel_Detection_As_Code/
├── .github/workflows/         # CI/CD automation for rule validation and deployment
│   └── sentinel-deploy.yml
├── detections/                # Organized by ATT&CK or CKC phase
│   ├── 01_Reconnaissance/
│   ├── 03_Initial_Access/
│   ├── 04_Execution/
│   ├── 06_Privilege_Escalation/
│   ├── 07_Defense_Evasion/
│   ├── 08_Credential_Access/
│   ├── 09_Discovery/
│   ├── 11_Collection/
│   ├── 12_Command_and_Control/
│   ├── 13_Exfiltration/
├── rule_creation_guidelines/ # Templates and best practices
│   ├── Rule Request Template.txt
│   └── YAML_Template.txt
├── README.md                  # This file
```

## ✅ Detection Rule Template

All detection rules follow a uniform schema that includes:

- Title and Description
- MITRE ATT&CK Technique and Tactic
- Kill Chain Phase Tag
- Lifecycle status (experimental, testing, production)
- Author and Date
- Logsource metadata
- Detection query (KQL)
- Known false positives
- Severity level
- Tags and classification

## 🧠 Example Tags

```yaml
tags:
  - attack.t1059.001
  - attack.execution
  - killchain.installation
  - data.source.DeviceProcessEvents
  - malware.family.powerview
```

## 🧪 Rule Lifecycle

We use the following tags to track deployment maturity:

- `experimental`: early-stage detection, not yet tuned
- `testing`: validated in test environments, under evaluation
- `production`: deployed and tuned in Microsoft Sentinel

## ⚙️ CI/CD Pipeline

The `.github/workflows/sentinel-deploy.yml` file defines the GitHub Actions pipeline to:

- Validate rule syntax
- Enforce tagging standards
- Deploy YAML-based detection rules to Microsoft Sentinel (via Azure DevOps or API integration)

## ✍️ Contribution Guide

1. Clone this repository
2. Create or edit rules in `detections/`
3. Follow the [YAML Template](rule_creation_guidelines/YAML_Template.txt)
4. Submit a PR and verify CI passes

# Sentinel Detection-as-Code

This repository contains detection rules and visualizations for Microsoft Sentinel, mapped to both MITRE ATT&CK and the Cyber Kill Chain (CKC). The goal is to enable a structured, lifecycle-aware detection engineering program.

## 📊 Detection Coverage Visuals

### MITRE Tactic Coverage Bar Chart
![Bar Chart](ckc_coverage_bar.png)

### MITRE Tactic Coverage Donut Chart
![Donut Chart](ckc_coverage_donut.png)

## 📁 Resources

- `coverage_matrix.csv` — Raw detection mapping
- `coverage_matrix.xlsx` — Excel version of the matrix
- `gap_closure_summary.md` — Summary of detection improvements


---

> Managed by the Detection Engineering Team
