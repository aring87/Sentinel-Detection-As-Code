# Triage Guide: MSHTA Launching Script or PowerShell

## Detection Title
MSHTA Launching Script or PowerShell

## Detection ID
SENT-EXEC-0002

## Objective

This detection identifies `mshta.exe` launching script interpreters or containing suspicious inline script, URL, or PowerShell indicators.

## Why It Matters

`mshta.exe` is a common LOLBin used to:
- execute inline script content
- fetch remote HTA or script content
- proxy PowerShell or script execution
- blend malicious execution into a trusted Windows binary

This behavior is especially important because `mshta.exe` is often abused in phishing, malware staging, and defense evasion. The broader normalized rule looks for `powershell`, `vbscript:`, `javascript:`, and HTTP/S indicators in the command line. :contentReference[oaicite:8]{index=8}

## Alert Logic Summary

The rule looks for:
- `mshta.exe`

with command lines containing:
- `powershell`
- `vbscript:`
- `javascript:`
- `http://`
- `https://` :contentReference[oaicite:9]{index=9}

## Initial Triage Questions

- Did `mshta.exe` reference a remote URL?
- Was the command line using inline script content?
- What parent process launched `mshta.exe`?
- Is `mshta.exe` normal on this device?
- Did child processes such as PowerShell or script hosts spawn afterward?

## Investigation Steps

1. Review the full `mshta.exe` command line.
2. Identify any embedded URLs, inline scripts, or script interpreter references.
3. Review the parent process and process ancestry.
4. Determine whether `mshta.exe` launched:
   - PowerShell
   - `cmd.exe`
   - script hosts
   - other LOLBins
5. Review related file and network activity.
6. Determine whether the host normally uses internal HTA-based tooling.

## Common False Positives

- legacy administrative or application compatibility workflows
- internal HTA-based tooling
- rare support or enterprise packaging scripts :contentReference[oaicite:10]{index=10}

## Escalation Guidance

Escalate when:
- a remote URL is present
- the command line includes inline script or PowerShell
- the parent process is suspicious
- `mshta.exe` is uncommon for the device
- there is follow-on execution, staging, or outbound traffic

## Recommended Enrichment

- full command line
- URL/domain reputation if present
- parent and child processes
- file writes and dropped content
- network connections
- user and host role
- nearby Office, browser, or phishing-related process activity

## ATT&CK Mapping

- Execution
- Defense Evasion
- T1218.005 – System Binary Proxy Execution: Mshta

## Related Rule

- `detections/sentinel/execution/mshta-launching-script-or-powershell.yml`