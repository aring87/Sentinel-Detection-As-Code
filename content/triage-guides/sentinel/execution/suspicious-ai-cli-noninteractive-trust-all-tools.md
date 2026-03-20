# Suspicious AI CLI Non-Interactive Trust-All-Tools Execution

## Goal
Identify risky AI CLI usage patterns that may allow untrusted tooling or prompt-injection-style abuse in non-interactive mode.

## Why This Alert Matters
AI developer tooling and MCP-style integrations can introduce new execution and data-access pathways. Non-interactive “trust-all-tools” behavior can enable broad automated access to code, files, or secrets.

## What the Detection Is Looking For
This detection looks for:
- AI-related CLI processes
- command-line flags or strings such as:
  - `--trust-all-tools`
  - `--no-interactive`
  - `mcp`
  - `model context protocol`
  - `amazon q`
  - `claude code`

## Initial Triage Questions
1. Is the endpoint an approved AI development system?
2. Was this run by an engineer or a non-technical user?
3. Did the command access repos, secrets, or internal files?
4. Did child processes or external connections follow?

## Key Evidence To Review
- full command line
- user role and host type
- child process chain
- repository, secret, or file-access events
- network destinations after execution

## Investigation Steps
1. Confirm whether the host is expected to run AI coding or agent tools.
2. Review whether the command bypassed interactive approval or tool restrictions.
3. Check for follow-on process creation, shell use, or file enumeration.
4. Look for code repo, secret store, or cloud access afterward.
5. Determine whether the activity fits prompt injection, agent abuse, or sanctioned development.

## Common Benign Explanations
- approved AI engineering workflows
- lab testing of agent tools
- internal development experimentation

## Escalate When
Escalate if:
- the host is not an approved engineering system
- trust-all-tools or non-interactive execution is unexplained
- follow-on shell, repo, or secret access occurs
- the same pattern appears on multiple endpoints

## Suggested Response Actions
- preserve command line and child-process telemetry
- review accessed files, repos, and credentials
- restrict or isolate the endpoint if sensitive data exposure is likely
- coordinate with engineering leadership if a shared AI workflow is involved

## Analyst Notes
This should remain experimental until you establish which AI tools are normal in your environment.