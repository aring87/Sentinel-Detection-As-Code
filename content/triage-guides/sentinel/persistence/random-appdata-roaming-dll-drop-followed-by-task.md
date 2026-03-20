# Random AppData Roaming DLL Drop Followed by Scheduled Task

## Goal
Identify suspicious DLL drops into random AppData\Roaming folders followed shortly by scheduled task creation.

## Why This Alert Matters
This is a strong persistence pattern for loader families that stage DLLs in user-writable paths and then create scheduled execution.

## What the Detection Is Looking For
This detection looks for:
- DLL creation in random-looking `AppData\Roaming` subfolders
- followed within 30 minutes by scheduled task creation

## Initial Triage Questions
1. Was the DLL path newly created?
2. Did the folder name appear random?
3. What process dropped the DLL?
4. What task was created afterward?

## Key Evidence To Review
- DLL file path and write time
- creating process
- scheduled task name and command
- download source of the original payload
- post-persistence network activity

## Investigation Steps
1. Review the DLL path and determine whether the folder looks random.
2. Identify the process that wrote the DLL.
3. Review the task created afterward and what it executes.
4. Correlate with network callbacks or second-stage downloads.
5. Check for masquerading software or installer lures.

## Common Benign Explanations
- rare installers using user roaming folders and tasks
- lab or malware-analysis testing

## Escalate When
Escalate if:
- folder name appears random
- DLL was dropped by an untrusted process
- scheduled task executes the same path
- the host shows additional persistence or C2

## Suggested Response Actions
- quarantine the endpoint if malicious behavior is confirmed
- capture the DLL, installer, and task definition
- hunt for matching folder/path patterns across endpoints

## Analyst Notes
This alert is especially valuable when the same pattern appears on multiple hosts.