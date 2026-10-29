# Microsoft source notes — Security Explorer 0.1

Official Microsoft documentation consulted October 23, 2026:

- [Understanding ADMX-backed policies](https://learn.microsoft.com/windows/client-management/understanding-admx-backed-policies): ADMX defines policies, scopes, categories, registry mapping; ADML localizes strings.
- [ADMX/ADML reference example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/07c916d4-dc30-4e32-a790-4b808b78fa00): links `displayName`, `explainText` and `.adml` `stringTable` entries.
- [Policy CSP documentation](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider): `Config` versus `Result` paths. Metadata/class discovery is not equivalent to querying CSP Result nodes.
- [secedit /export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export): read/export syntax, area selection and merged policy caveat.
- [auditpol /get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get): advanced audit policy retrieval and authorization requirements.
- [Defender Get-MpComputerStatus](https://learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus): antimalware runtime data source.
- [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile): `ActiveStore` includes active policy from applicable stores.
- [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule): active firewall rule inventory.
- [Get-AppLockerPolicy](https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy): `-Effective` is GP-only and does not include CSP deployments.
- [Security Compliance Toolkit](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10): baselines and Policy Analyzer, **not** automatically included in this tool.

Design decision: catalog official locally installed definitions without interpreting every entry as configured or applicable; collect selected authorized observed values independently; preserve sources and failures; do not mutate protections or export secret material.
