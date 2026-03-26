# Triage Guide: Quick Assist Followed by WinSCP or Google Drive Exfiltration Activity

## What this detects
Quick Assist followed by WinSCP execution or Google Drive access on the same device within a short window.

## Why it matters
This mirrors vishing-driven intrusion activity that rapidly moves from remote support access to exfiltration.

## Immediate questions
1. Was the Quick Assist session expected and approved?
2. Who initiated the session and from where?
3. Was WinSCP actually executed, and what files were targeted?
4. Was Google Drive accessed by a browser, WinSCP, rclone, or another tool?

## Investigative steps
- Validate the help desk ticket or user support request.
- Review Quick Assist process ancestry and network activity.
- Inspect WinSCP command line, session logs, and touched files.
- Query DeviceNetworkEvents for Google Drive or other cloud storage access.
- Check shared drive enumeration, archive creation, and staging directories.

## Escalation indicators
- No legitimate support ticket
- Immediate file collection after Quick Assist
- WinSCP plus cloud storage fallback behavior
- Sensitive data staged or compressed before transfer

## Likely false positives
- Legitimate remote support with approved file transfer
- Internal support staff accessing sanctioned cloud storage
