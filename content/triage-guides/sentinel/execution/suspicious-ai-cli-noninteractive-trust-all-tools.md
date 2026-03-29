# Suspicious AI CLI Noninteractive Trust-All-Tools Execution

## Goal
Identify noninteractive AI CLI execution with broad approval or trust-all-tools flags that may enable unattended risky tool use or agentic execution.

## Why This Alert Matters
AI command-line tools are increasingly being used in development, automation, and lab workflows. When these tools run noninteractively with broad approval flags, they may gain the ability to make changes, call tools, or access data with reduced human review. In some environments this may be normal, but in others it can introduce execution, data access, or automation risk that deserves investigation. This guide is based on a rule that looks for AI CLI tools executed with flags such as `--non-interactive`, `--yes`, `--force`, `--trust-all-tools`, and similar broad-approval settings. :contentReference[oaicite:25]{index=25}

## What the Detection Is Looking For
This detection reviews `DeviceProcessEvents` for AI CLI tools such as:
- `claude.exe`
- `claude.cmd`
- `aider.exe`
- `aider.cmd`
- `cursor.exe`
- `gemini.exe`
- `gemini.cmd`
- `openai.exe`
- `openai.cmd`

It also looks for command lines referencing those tools, combined with flags such as:
- `--non-interactive`
- `--yes`
- `--force`
- `--dangerously-skip-permissions`
- `--trust-all-tools`
- `--approve-all` :contentReference[oaicite:26]{index=26}

## Likely ATT&CK Mapping
- **T1059** – Command and Scripting Interpreter

## Initial Triage Questions
1. Which AI CLI tool was used?
2. Was the host expected to run AI development or automation tooling?
3. Which broad-approval or trust-all-tools flags were present?
4. Did the tool run under a developer, service, or normal user account?
5. Was the execution interactive or fully unattended?
6. Did the process make file changes, spawn other tools, or access secrets?
7. Was the device an approved engineering asset or an unexpected endpoint?

## Key Fields To Review
- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `SHA1`
- `ReportId`

## Investigation Steps

### 1. Validate host and user context
- Determine whether the host is:
  - engineering workstation
  - CI/CD runner
  - lab system
  - ordinary user endpoint
- Confirm whether the user is expected to run AI tooling.

### 2. Review approval flags and execution mode
- Identify whether the tool was launched with:
  - noninteractive mode
  - automatic approval
  - permission bypass
  - force flags
- Higher-risk flags deserve more scrutiny.

### 3. Review follow-on activity
Look for:
- file modification
- code execution
- shell command invocation
- secret or credential access
- network egress
- archive creation
- outbound API calls or service access

### 4. Assess source and deployment path
- Check whether the binary is:
  - approved
  - signed
  - installed in a normal engineering path
  - launched from Temp, Downloads, or AppData
- Unexpected pathing significantly increases suspicion.

### 5. Validate legitimate automation
- Confirm whether the activity maps to:
  - sanctioned CI/CD workflows
  - internal AI-assisted development
  - lab experimentation
- If the execution occurred on a non-engineering system, treat it more seriously.

## Common Benign Explanations
- Approved engineering automation using AI tooling in CI or controlled lab environments
- Internal development workflows with sanctioned noninteractive agents :contentReference[oaicite:27]{index=27}

## Escalate When
Escalate if:
- the host is not an approved engineering or lab asset
- the tool runs with broad approval or dangerous permission flags
- the binary is launched from a suspicious or user-writable path
- the process performs unexpected file, credential, or network actions
- the activity appears on a user endpoint with no development context

## Suggested Response Actions
- Preserve the full process telemetry and command line
- Review spawned tools, file changes, and nearby network activity
- Validate whether the binary and workflow are approved
- Search for the same AI CLI usage elsewhere in the environment
- Restrict or review AI CLI usage on non-engineering endpoints if needed
- Tune based on known engineering and automation baselines

## Analyst Notes
This is an environment-sensitive analytic. In engineering-heavy organizations it may need careful allowlisting or context-based triage, but on ordinary endpoints it can be a strong signal of unexpected or risky automated execution.