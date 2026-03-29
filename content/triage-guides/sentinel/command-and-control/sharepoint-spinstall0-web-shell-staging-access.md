# SharePoint SPInstall0 or Web Shell Staging Access

## Goal
Identify access or staging activity involving suspicious SharePoint setup paths or likely web shell staging locations that may indicate malicious persistence or server-side abuse.

## Why This Alert Matters
Attackers targeting SharePoint and similar platforms may stage tools, payloads, or web shells in locations that resemble installation, configuration, or maintenance paths. Activity involving unusual setup-related file paths or suspicious staging behavior can indicate server compromise, persistence preparation, or post-exploitation tool placement.

## What the Detection Is Looking For
This detection looks for suspicious access patterns related to SharePoint installation or web shell staging indicators, including references to paths or content associated with:
- `spinstall0`
- suspicious setup artifacts
- unusual script or shell staging behavior
- files or paths consistent with web shell placement

The analytic is environment-specific and should be interpreted in the context of how SharePoint is deployed and administered in your environment.

## Likely ATT&CK Mapping
- **T1505.003** – Server Software Component: Web Shell
- **T1105** – Ingress Tool Transfer

## Initial Triage Questions
1. Is the affected server a SharePoint host or related application server?
2. Is the path normal for installation, patching, or maintenance?
3. Was the access tied to a known administrator, installer, or service account?
4. Do the accessed files resemble scripts, ASPX pages, archives, or other staged payloads?
5. Did the activity occur during a maintenance window?
6. Is there evidence of suspicious web requests, process execution, or IIS activity nearby?
7. Was there follow-on persistence, credential access, or outbound transfer?

## Key Fields To Review
- `TimeGenerated`
- `OperationName` or `ActionType`
- `UserId` or initiating actor
- file or object path
- accessed or modified object name
- source IP
- related process or server-side execution context

## Investigation Steps

### 1. Validate the file or path involved
- Review the exact path or object referenced.
- Determine whether it is:
  - a known SharePoint installation path
  - a setup or staging directory
  - a suspicious or newly created web-accessible path
- Pay close attention to:
  - `.aspx`
  - `.ashx`
  - `.config`
  - archives
  - unusual script files

### 2. Review actor context
- Identify the user, service account, or application responsible.
- Determine whether the actor normally performs SharePoint administration or deployment activity.
- Confirm whether the timing aligns with:
  - patching
  - upgrade work
  - migration
  - farm maintenance

### 3. Check for web shell indicators
Look for:
- suspicious ASPX files
- recently modified web-accessible content
- unexpected command execution on the server
- encoded or obfuscated content
- outbound connections from IIS or SharePoint-associated processes
- follow-on file writes or archive creation

### 4. Correlate with server-side activity
- Review IIS logs and relevant process telemetry.
- Check for:
  - `w3wp.exe`
  - PowerShell
  - CMD
  - MSHTA
  - `rundll32.exe`
  - script interpreter execution
- Determine whether the access preceded or followed suspicious server-side execution.

### 5. Validate business context
- Confirm whether the activity aligns with normal SharePoint deployment or maintenance.
- Review CAB records, change windows, or admin notes.
- If there is no expected business reason, treat the activity more seriously.

## Common Benign Explanations
- SharePoint installation or patching
- Approved farm maintenance
- Migration or upgrade activity
- Developer or admin configuration testing
- Planned setup artifact access during controlled deployment

## Escalate When
Escalate if:
- the path is web-accessible and contains suspicious script content
- the activity is not tied to a known administrator or maintenance window
- IIS or SharePoint processes show follow-on suspicious execution
- the accessed files appear newly created, obfuscated, or masqueraded
- there is evidence of web shell behavior, outbound staging, or credential theft

## Suggested Response Actions
- Preserve file, web, and process telemetry from the affected server
- Collect the suspicious file or page content for analysis
- Review IIS and SharePoint logs around the event
- Isolate the server if malicious server-side code execution is confirmed
- Search the environment for the same filenames, hashes, or path patterns
- Validate integrity of web content and recent administrative changes

## Analyst Notes
This is a niche but high-value analytic for organizations that run SharePoint or similar server software. It is strongest when paired with web logs, IIS process telemetry, suspicious child processes, or evidence of ASPX or script-based staging.