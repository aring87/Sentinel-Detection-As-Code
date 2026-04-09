# Splunk Production-Tuned Conversion Pack

This is the second-pass tuning package for the Sentinel-to-Splunk conversion.

## Summary
- Active converted rules: 75
- Production-ready candidates: 70
- Validation-required candidates: 5
- Deprecated rules preserved separately: 22

## What changed in this pass
- Normalized first-pass SPL syntax that still contained KQL habits such as `!in~`, `!has`, `between (...)`, and unresolved `project` fragments.
- Replaced broken time-window joins with `relative_time(...)` comparisons where appropriate.
- Promoted reviewed rules to `status: production` and `lifecycle: production`.
- Added consistent implementation and production tuning guidance to each active rule.
- Kept complex cloud and Entra correlation detections in testing status when they still depend on environment-specific nested fields or multi-source joins.

## Production candidates
- browser/browser-extension-install-from-temp-or-user-profile.yml
- collection/Clipboard-Data-Collection.yml
- collection/data-from-local-system.yml
- collection/graph-mail-access-burst.yml
- collection/mass-file-enumeration-in-user-data-paths.yml
- collection/screen-capture-utility-execution.yml
- command-and-control/powershell-or-lolbin-external-network-traffic.yml
- command-and-control/quick-assist-or-rmm-followed-by-script-execution.yml
- command-and-control/sharepoint-spinstall0-or-webshell-staging-access.yml
- command-and-control/suspicious-web-download-via-certutil-or-bitsadmin.yml
- credential-access/device-code-phishing-followed-by-graph-mail-access.yml
- credential-access/potential-lsass-memory-dump.yml
- credential-access/potential-ntlm-enumeration-via-failed-logons.yml
- credential-access/suspicious-browser-credential-store-access.yml
- credential-access/vmware_vmdk_ntds_theft.yml
- defense-evasion/clear-windows-event-logs.yml
- defense-evasion/disable-script-block-logging.yml
- defense-evasion/powershell-script-block-logging-disabled.yml
- defense-evasion/security-tool-disable-attempt.yml
- discovery/dns-enumeration-via-command-line-tools.yml
- discovery/ldap-enumeration-using-powershell.yml
- discovery/net-group-and-domain-trust-discovery.yml
- discovery/Net-User-Enumeration.yml
- discovery/system-and-network-configuration-discovery.yml
- execution/fake_captcha_browser_to_script.yml
- execution/malicious-and-paste-powershell-from-explorer.yml
- execution/mshta-launching-script-or-powershell.yml
- execution/oauth-redirection-abuse-followed-by-browser-download.yml
- execution/powershell-encoded-command-execution.yml
- execution/powershell-encoded-command-from-temp-folder.yml
- execution/suspicious-ai-cli-noninteractive-trust-all-tools.yml
- exfiltration/archive-creation-followed-by-external-transfer.yml
- exfiltration/azcopy-or-cloud-cli-bulk-export.yml
- exfiltration/exfiltration-uncommon-port.yml
- exfiltration/Onedrive-File-Exfil.yml
- exfiltration/onedrive-or-cloud-storage-bulk-upload-spike.yml
- exfiltration/powershell-email-exfiltration-with-attachments.yml
- exfiltration/quick_assist_winscp_google_drive.yml
- exfiltration/sharepoint-or-onedrive-bulk-download-by-newly-risky-user.yml
- impact/boot-configuration-or-recovery-tampering.yml
- impact/mass-file-rename-or-encryption-burst.yml
- impact/remote_smb_encryption.yml
- impact/volume-shadow-copy-deletion.yml
- initial-access/device-code-sign-in-followed-by-device-registration.yml
- initial-access/multiple-user-device-code-sign-ins.yml
- initial-access/oauth-redirection-abuse-url-click.yml
- initial-access/potential-spearphishing-attachment-execution.yml
- initial-access/suspicious-external-remote-service-sign-in.yml
- initial-access/teams-external-contact-followed-by-quick-assist.yml
- lateral-movement/remote-scheduled-task-creation.yml
- lateral-movement/remote-service-creation.yml
- lateral-movement/wmi-remote-process-execution.yml
- persistence/cleanup-loader-scheduled-task-rundll32-dllregisterserver.yml
- persistence/m365_inbox_rule_forward_delete.yml
- persistence/nodejs-guid-installer-scheduled-task.yml
- persistence/random-appdata-roaming-dll-drop-followed-by-task.yml
- persistence/registry-run-key-modification.yml
- persistence/service-binary-path-hijack.yml
- persistence/suspicious-scheduled-task-creation.yml
- privilege-escalation/dll-injection.yml
- privilege-escalation/event-viewer-uac-bypass-registry-hijack.yml
- privilege-escalation/suspicious-service-creation-for-elevation.yml
- privilege-escalation/suspicious-token-manipulation-or-sedebug-use.yml
- reconnaissance/External-Lookup-Tool-Usage.yml
- reconnaissance/external-network-scanner-execution.yml
- reconnaissance/whoami-and-net-enumeration-burst.yml
- resource-development/bulk-mailbox-or-rule-creation.yml
- resource-development/suspicious-azure-ad-application-registration.yml
- resource-development/suspicious-trufflehog-secret-scanning.yml
- resource-development/user-click-spike-to-suspicious-domain.yml

## Validation-required rules
- exfiltration/cloud-storage-public-access-or-immutability-removal.yml
- impact/cloud-backup-or-storage-mass-delete-burst.yml
- persistence/entra_control_plane_abuse.yml
- resource-development/new-app-secret-added-then-service-principal-signin.yml
- resource-development/sharepoint-third-party-integration-secret-access.yml

## Deployment guidance
1. Point each source macro to the correct index, sourcetype, or accelerated datamodel.
2. Validate field aliases for Microsoft Defender, Office 365, Azure Activity, AuditLogs, and URL click telemetry.
3. Start rules in a lower-noise schedule with suppression and allowlists for IT/admin activity.
4. Promote to notable or risk-based alerting only after baseline review.

## Important note
The 5 validation-required rules are not broken, but they still need hands-on field mapping in your Splunk environment because the original Sentinel logic depends on source-specific cloud schemas and nested JSON arrays.
