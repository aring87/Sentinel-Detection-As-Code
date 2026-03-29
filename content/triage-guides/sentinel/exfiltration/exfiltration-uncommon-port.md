# Exfiltration Over Uncommon Port

## Goal
Identify high-volume outbound transfer activity to external destinations over uncommon ports that may indicate nonstandard exfiltration channels.

## Why This Alert Matters
Attackers do not always use standard web ports for exfiltration. They may send data over unusual ports to blend with niche applications, evade simple monitoring, or use custom tooling. High outbound volume over nonstandard ports can indicate data removal, custom transfer tooling, or staged beaconing with exfil capability. This guide is based on a rule that looks for external traffic on ports outside a common allowlist and highlights cases with high `SentBytes`. :contentReference[oaicite:18]{index=18}

## What the Detection Is Looking For
This detection reviews `DeviceNetworkEvents` where:
- the destination is external
- the remote port is not one of several common ports such as 80, 443, 22, 53, 25, 587, or 3389
- total sent bytes exceed a high threshold

It summarizes by device, process, command line, remote IP, and remote port. :contentReference[oaicite:19]{index=19}

## Likely ATT&CK Mapping
- **T1048.003** – Exfiltration Over Alternative Protocol: Unencrypted/Obscure Non-C2 Protocol

## Initial Triage Questions
1. Which process generated the transfer?
2. Which port and destination were involved?
3. Is the port expected for the application or device role?
4. How much data was sent?
5. Was there preceding collection or archive creation?
6. Is the destination approved or suspicious?
7. Does the process normally communicate externally at all?

## Key Fields To Review
- `DeviceName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `RemoteIP`
- `RemotePort`
- `SentBytes`
- `ConnCount`
- `URLs`
- `Timestamp`

## Investigation Steps

### 1. Review the process and port
- Identify the initiating process.
- Determine whether the port is:
  - expected for the software
  - unusual for the device role
  - associated with custom transfer tooling
- Review the process path and signer if available.

### 2. Assess data volume
- Confirm how much data was sent and over what time window.
- Determine whether the volume is consistent with:
  - backup
  - replication
  - sync
  - suspicious exfiltration

### 3. Investigate the destination
- Review the destination IP, domain, and any related URLs.
- Determine whether the destination is:
  - internal or partner infrastructure
  - cloud service
  - personal endpoint
  - suspicious or unknown host
- Check whether the IP or domain appears elsewhere in the environment.

### 4. Correlate with preceding collection or staging
Look for:
- archive creation
- mass file access
- cloud export tools
- browser credential store access
- PowerShell staging
- email exfiltration
- removable media activity

### 5. Validate business purpose
- Confirm whether the process belongs to:
  - backup software
  - replication platform
  - engineering tool
  - vendor product
- If not, treat the alert as higher priority.

## Common Benign Explanations
- Approved applications using nonstandard transfer ports
- Backup or replication tools
- Specialized vendor or engineering software :contentReference[oaicite:20]{index=20}

## Escalate When
Escalate if:
- the process is unusual or unapproved
- the remote port is not expected for the application
- there is high outbound volume to a suspicious destination
- there are preceding collection or staging indicators
- the same host shows other exfiltration or C2 behavior

## Suggested Response Actions
- Preserve network and process telemetry
- Validate destination ownership and business purpose
- Review whether data transferred included sensitive content
- Block or investigate suspicious destinations
- Search for the same port and process pattern on other systems
- Isolate the endpoint if malicious exfiltration is likely

## Analyst Notes
This is a useful “transport anomaly” analytic. It is best handled by first determining whether the process and port combination is normal for the host, then correlating with collection or staging indicators.