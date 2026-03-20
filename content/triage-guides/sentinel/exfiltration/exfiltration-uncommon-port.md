# Exfiltration Over Uncommon Port

## Goal
Identify large outbound transfers over non-standard ports that may represent data exfiltration.

## Why This Alert Matters
Attackers often avoid common web ports when moving data, especially if they are using custom services, tunneling, or alternate protocols. Large outbound byte volumes over uncommon ports can indicate unauthorized transfer activity.

## What the Detection Is Looking For
This detection looks for outbound network events where:
- the remote port is not one of the common ports such as `80`, `443`, `22`, or `53`
- sent bytes exceed a significant threshold

## Likely ATT&CK Mapping
- T1048.003 – Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol

## Initial Triage Questions
1. What process generated the traffic?
2. What is the destination IP and port?
3. Is the destination trusted, internal, or expected?
4. Was the byte volume abnormal for this device or user?
5. Was there collection or archive activity before the transfer?

## Key Fields To Review
- TimeGenerated
- DeviceName
- RemoteIP
- RemotePort
- SentBytes

## Investigation Steps
### 1. Validate the transfer
- Confirm the destination IP and remote port.
- Review total bytes sent and whether the activity was sustained or bursty.
- Determine whether the traffic was internal, external, or over VPN/proxy infrastructure.

### 2. Identify the source process
- Pivot to process telemetry for the same timeframe.
- Determine which executable initiated the connection.
- Look for:
  - PowerShell
  - scripting engines
  - compression tools
  - custom binaries
  - data transfer utilities
  - browser or sync clients behaving abnormally

### 3. Evaluate destination reputation and business purpose
- Identify owner or ASN of the destination if known internally.
- Determine whether the host normally communicates with that IP/port.
- Check whether the port is used by any sanctioned application in your environment.

### 4. Correlate with staging behavior
Search for recent:
- archive creation
- mass file access
- temp folder staging
- clipboard or screenshot collection
- cloud upload or email exfil behavior

### 5. Assess user and host context
- Is the host a server, workstation, jump box, or developer system?
- Is the account privileged?
- Is there an approved business use for the application or destination?

## Common Benign Explanations
- sanctioned line-of-business applications using uncommon ports
- backup or replication software
- developer or lab tools
- remote administration or appliance communication

## Escalate When
Escalate if:
- destination is external and unrecognized
- process lineage is suspicious
- transfer volume is large and unexplained
- the port is rare in your environment
- staging or collection alerts occurred beforehand

## Suggested Response Actions
- preserve network session details and associated process telemetry
- block or contain the destination if malicious activity is active
- isolate the endpoint if needed
- review firewall, proxy, and EDR telemetry for the same time period
- notify incident response for possible data loss assessment

## Analyst Notes
This analytic becomes much stronger when correlated with archive creation, email exfiltration, or cloud upload activity on the same device or account.