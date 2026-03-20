# Exception Management

## Purpose

Exception management defines how approved deviations from standard detection behavior, coverage expectations, or operational requirements are documented, reviewed, and maintained.

The purpose of this process is to allow flexibility without losing visibility, accountability, or governance.

---

## What Is an Exception

An exception is an approved and documented allowance for a detection, process, or standard to operate outside the expected baseline.

Examples include:
- known false-positive sources that are temporarily suppressed
- approved exclusions for administrative tools or service accounts
- delayed remediation of a noisy detection
- temporary acceptance of missing documentation
- approved deviation from naming, lifecycle, or quality standards
- delayed onboarding of a data source required for a detection use case

---

## Exception Principles

Exceptions should be:
- documented
- approved
- time-bounded when possible
- reviewed periodically
- traceable to a business, technical, or operational reason

Exceptions should not become permanent shortcuts without review.

---

## Exception Categories

### Detection Logic Exceptions
Used when certain hosts, users, tools, or processes must be excluded to reduce known false positives.

### Coverage Exceptions
Used when a required ATT&CK use case cannot yet be covered due to telemetry or platform limitations.

### Process Exceptions
Used when a required review, validation, or documentation step cannot be completed on schedule.

### Governance Exceptions
Used when a rule or artifact temporarily does not meet standard naming, metadata, or ownership requirements.

---

## Required Exception Information

Every exception should document:
- exception title
- related detection or process
- exception category
- reason for the exception
- scope of the exception
- requestor
- approver
- date approved
- review date
- expiration date if applicable
- associated notes or ticket reference

---

## Approval Guidance

Approval should be risk-based.

### Low-Risk Exceptions
Examples:
- temporary documentation gaps
- known benign operational noise with clear ownership

May be approved by:
- detection engineering lead
- designated content owner

### Higher-Risk Exceptions
Examples:
- excluding high-value admin accounts
- disabling or heavily suppressing important detection logic
- prolonged lack of validation for critical detections

May require:
- detection engineering lead
- SOC leadership
- security management, depending on impact

---

## Review Cadence

Exceptions should be reviewed regularly.

Recommended review cadence:
- monthly for active detection logic exceptions
- quarterly for coverage and governance exceptions
- immediately when the underlying condition changes

Exceptions should be removed as soon as the reason for the exception no longer exists.

---

## Expiration Guidance

Whenever possible, exceptions should include an expiration date.

Examples:
- 30 days for a temporary false-positive suppression
- 60–90 days for a process or documentation exception
- quarterly review for coverage exceptions tied to missing telemetry

If no expiration is defined, the exception should still be assigned a review date.

---

## Exception Outcomes

At review time, an exception should be:
- renewed
- modified
- removed
- escalated for risk discussion

---

## Exception Tracking

Exceptions should be tracked in a consistent format such as:
- CSV
- tracker sheet
- issue workflow
- markdown register

The tracking mechanism should allow quick visibility into:
- active exceptions
- upcoming expirations
- owners
- affected detections or processes
- risk level

---

## Recommended Repository Placement

Examples of exception documentation locations:
- `docs/02_process/exception-management.md` for process guidance
- a future `exceptions/` folder or CSV register
- issue templates for exception requests

---

## Example Use Cases

### Example 1
A PowerShell detection produces high false positives from an approved software deployment platform. A temporary exclusion is approved for the deployment service account while better logic is developed.

### Example 2
A detection is missing full triage guidance but is still needed in testing. A short-term documentation exception is approved with a 30-day review.

### Example 3
A key ATT&CK technique cannot yet be covered because the required telemetry is not ingested. A coverage exception is documented until the data source is onboarded.

---

## Goals of Exception Management

The exception process exists to:
- preserve operational flexibility
- reduce unmanaged risk
- maintain visibility into known gaps
- keep the program honest about deviations
- support continuous improvement rather than silent workarounds