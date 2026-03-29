# Rewritten Triage Guides

This package contains rewritten markdown triage guides using the fuller analyst-playbook format adopted across the repository.

These guides were rewritten to better align detection content with operational analyst needs and to provide more consistent investigation flow across rules.

## Format Used Across Guides

The standard structure used across these guides includes:

- Goal
- Why This Alert Matters
- What the Detection Is Looking For
- Likely ATT&CK Mapping
- Initial Triage Questions
- Key Fields To Review
- Investigation Steps
- Common Benign Explanations
- Escalate When
- Suggested Response Actions
- Analyst Notes

## Purpose

These rewritten guides are intended to:

- improve analyst usability
- make alerts easier to investigate consistently
- provide clearer escalation guidance
- align triage content more closely to underlying detection logic
- support a more mature detection engineering workflow

## Relationship to Repository Content

These guides follow the same fuller style used in the `registry-run-key-modification.md` guide and are intended to support continued standardization across the triage guide library.

Where applicable, these guides should eventually live in the main `content/triage-guides/` structure under their appropriate category or workflow location.

## Files Included

- `fake_captcha_browser_to_script.md`
- `quick_assist_winscp_google_drive.md`
- `vmware_vmdk_ntds_theft.md`
- `remote_smb_encryption.md`
- `entra_control_plane_abuse.md`
- `m365_inbox_rule_forward_delete.md`
- `ad_explorer_or_secrets_dump_tool_on_vdi_or_admin_host.md`
- `browser_or_quick_assist_session_followed_by_google_drive_exfiltration_utility.md`
- `broadening_of_edr_exclusion_or_suppression_rule_scope.md`
- `device_code_or_oauth_authorization_abuse_against_microsoft_365.md`
- `suspicious_npm_package_execution_or_install_with_embedded_credential_theft_behavior.md`
- `langflow_or_ai_workflow_platform_exploitation_followed_by_persistence_or_malware_deployment.md`
- `prompt_injection_or_hidden_instruction_pattern_in_inbound_email_content.md`

## Notes

This package is best treated as a staging or working set for triage-guide standardization. As guides are reviewed and finalized, they should be moved into the primary repository structure and maintained alongside their related detections and supporting content.