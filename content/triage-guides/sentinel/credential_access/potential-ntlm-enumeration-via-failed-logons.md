# Potential NTLM Enumeration via Failed Logons

## Goal
Identify spikes in failed NTLM authentication from a single source that may indicate account enumeration, password spraying, or credential discovery activity.

## Why This Alert Matters
Repeated NTLM logon failures across many accounts can indicate an attacker testing usernames, validating account existence, or attempting low-and-slow spraying. Even when no successful logon occurs, this behavior may be an early sign of credential-access activity and can be valuable for detecting compromised systems or attacker reconnaissance.

## What the Detection Is Looking For
This detection reviews `IdentityLogonEvents` for:
- `Protocol =~ "NTLM"`
- `ActionType =~ "LogonFailed"`

It then summarizes failures by:
- `DeviceName`
- `IPAddress`
- 15-minute time window

The rule triggers when:
- failures are high
- multiple accounts are targeted in the same window

## Likely ATT&CK Mapping
- **T1110.003** – Password Spraying
- **T1087** – Account Discovery

## Initial Triage Questions
1. Which source IP generated the failed NTLM attempts?
2. How many accounts were targeted?
3. Were the targeted accounts valid, privileged, stale, or service accounts?
4. Did any successful logons follow the failures?
5. Is the source system misconfigured, compromised, or performing expected authentication?
6. Is the source internal, external, or tied to a known relay/proxy path?
7. Are there related lateral movement, lockouts, or remote access attempts nearby?

## Key Fields To Review
- `DeviceName`
- `IPAddress`
- `Timestamp`
- `Failures`
- `Accounts`

## Investigation Steps

### 1. Identify the source
- Determine the host and IP responsible for the NTLM failures.
- Confirm whether the source is:
  - a workstation
  - server
  - scanner
  - legacy device
  - known misconfigured system

### 2. Review targeted accounts
- Identify whether the targeted accounts are:
  - normal users
  - admins
  - service accounts
  - disabled or stale accounts
- Look for patterns such as alphabetic enumeration, role-based targeting, or known high-value users.

### 3. Check for successful follow-on access
- Search for successful NTLM, Kerberos, or interactive logons after the failures.
- Prioritize cases where one or more targeted accounts later succeeded.

### 4. Correlate with other behavior
Look for:
- account lockouts
- remote SMB access
- WMI or scheduled-task activity
- service creation
- LSASS dumping
- browser credential access
- outbound staging or exfiltration

### 5. Validate benign explanations
- Determine whether the activity may reflect:
  - stale credentials in a service
  - legacy authentication loops
  - password spray testing in an approved exercise
  - misconfigured scripts or mapped drives

## Common Benign Explanations
- Misconfigured services or stale credentials
- Approved password spray simulations
- Legacy systems repeatedly attempting invalid NTLM auth
- Broken scripts or scheduled tasks using outdated passwords

## Escalate When
Escalate if:
- the number of targeted accounts is high
- the source system is not expected to authenticate broadly
- the same source later shows successful authentication
- the failures target privileged or sensitive accounts
- the host also shows lateral movement or credential-access behavior
- the source appears compromised or attacker-controlled

## Suggested Response Actions
- Preserve authentication logs and correlated endpoint events
- Investigate and contain the source system if suspicious
- Review password hygiene and lockout activity for targeted users
- Search for successful follow-on logons from the same IP or host
- Reset credentials or disable compromised accounts if needed
- Tune or suppress only after clearly confirming benign misconfiguration

## Analyst Notes
This is a strong early-warning detection for credential-access activity. Not every event is malicious, but high-volume failed NTLM activity across many users should be investigated carefully, especially when followed by a successful sign-in or lateral movement.