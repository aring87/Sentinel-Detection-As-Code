# Suspicious npm Package Execution or Install With Embedded Credential Theft Behavior

## Goal
Identify potentially malicious package installation or Node.js execution on developer systems that may indicate supply chain abuse, credential theft, or postinstall script execution.

## Why This Alert Matters
CrowdStrike called out malicious packages and compromised software supply chain workflows as a major risk area. npm and related Node.js tooling can execute install scripts automatically, which gives attackers an opportunity to steal tokens, read configuration files, or stage follow-on payloads in developer environments. These systems often hold source code, cloud credentials, package tokens, and AI or API secrets.

## What the Detection Is Looking For
This detection reviews process creation telemetry for:
- processes such as:
  - `node.exe`
  - `npm.cmd`
  - `npm.exe`
  - `npx.cmd`
  - `npx.exe`
- command-line arguments referencing:
  - `postinstall`
  - `preinstall`
  - `.npmrc`
  - `token`
  - `credential`
  - `wallet`
  - `seed phrase`
  - AI-related secret terms

## Likely ATT&CK Mapping
- T1195 – Supply Chain Compromise
- T1059.007 – JavaScript
- T1552 – Unsecured Credentials
- T1078 – Valid Accounts

## Initial Triage Questions
1. Which package or script triggered the execution?
2. Was the system a developer workstation, CI runner, or build server?
3. Did the process read or reference `.npmrc`, environment secrets, wallets, or tokens?
4. Was this tied to a newly installed dependency or unexpected package update?
5. Did the activity lead to external network connections, staging, or persistence?

## Key Fields To Review
- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine
- InitiatingProcessFileName
- project path or working directory if available
- network destinations
- package name and version if available

## Investigation Steps
### 1. Validate the package execution
- Identify whether the process was:
  - package installation
  - `postinstall` execution
  - `preinstall` execution
  - ad hoc Node.js script use
- Determine which project directory and dependency were involved.

### 2. Inspect secret access behavior
- Review whether the process touched:
  - `.npmrc`
  - cloud credential files
  - API key stores
  - developer tokens
  - wallet or secret material
- Check for environment-variable harvesting or config file reads.

### 3. Review network behavior
Look for:
- package registry access beyond expected domains
- unusual outbound connections
- paste sites or file-sharing services
- GitHub gists or raw content downloads
- cloud-storage or webhook destinations

### 4. Correlate with developer environment context
- Determine whether the system is:
  - a developer workstation
  - CI/CD runner
  - build server
  - admin workstation
- Prioritize systems with source code access or production deployment permissions.

### 5. Validate business context
- Confirm whether the package and workflow are expected.
- Review recent dependency changes, pull requests, lockfile updates, or build failures.
- Coordinate with development owners before classifying a package action as benign.

## Common Benign Explanations
- Legitimate package install scripts
- Normal developer build workflows
- CI/CD package installation
- Authorized use of AI or API tooling in development

## Escalate When
Escalate if:
- the package is unknown, typosquatted, or recently introduced unexpectedly
- the process reads secret stores or token files without a valid reason
- unusual outbound connections occur during install
- the same host shows persistence, credential access, or repo tampering
- the activity impacts CI/CD or shared developer infrastructure

## Suggested Response Actions
- preserve package names, versions, command lines, and working directories
- identify whether secrets or tokens were exposed
- block or remove the malicious dependency if confirmed
- notify development and CI/CD owners
- rotate exposed secrets and review source repositories for related compromise

## Analyst Notes
Developer tooling alerts need both security and engineering context. The package name, lockfile change, install script, and secret access pattern usually tell the story faster than the process name alone.
