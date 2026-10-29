# Windows Security Settings Explorer

A **read-only** graphical security inventory for Windows 11 (also usable on other compatible Windows installations). Windows PowerShell 5.1, Windows Forms, built-in Windows cmdlets, `secedit` and `auditpol`; no third-party dependencies, policy changes, network requests or downloads.

Security Explorer brings policy definitions, configuration observations, and
runtime status into a searchable interface with a separate evidence view.
It helps answer what a source reports and what remains unknown. It does not
turn the presence of a setting into proof of effective protection.

The source identifies version **0.1.1**, with the later UI, manual-collection,
auditing-query, and partial-inventory changes described below. This is a
development build with recorded sample-data checks; live coverage and
machine-specific behavior still require validation.

## What a session shows

Start a collection explicitly, browse the results by domain, and read the
description alongside its source and limitations. Search and row selection use
the displayed snapshot rather than silently repeating live collection.

The interface distinguishes the latest partial inventory from the last complete
run. Failed records stay visible as evidence. A failed or interrupted refresh
does not silently replace a previous complete snapshot, and the GUI only
exports a selected complete run.

Here, **complete** describes the collector sequence and its failure records.
It does not mean every possible security control was discovered or verified.

**Read next:** [Start](#start) · [Sources and scope](#sources-and-scope) ·
[Interpretation](#interpretation) · [Source map](#source-map-and-contribution) ·
[Validation limits](#limitations-and-test-status).

## Start

1. Download or clone the repository and keep all files together.
2. Run `Launch-SecurityExplorer.cmd` on Windows 11. This respects your machine's PowerShell execution policy. Alternatively run `powershell.exe -NoProfile -STA -File .\SecurityExplorer.ps1` from an authorized Windows PowerShell session.
3. Click **Collect / refresh inventory** to read live data. Opening the window does not start collection. Select a category on the left and search using the top text box. Select a row to see its description and its separate evidence/reference view.
4. Select **Export JSON** to save a sanitized local inventory. The JSON still contains sensitive information about your system's security posture. Do not upload it publicly.

To run **without a GUI** and export to JSON:

```powershell
powershell.exe -NoProfile -File .\SecurityExplorer.ps1 -InventoryOnly -OutputPath .\SecurityInventory.json
```

The `Export-Inventory.cmd` launcher runs the same inventory and writes a JSON file beside the application. Run in an approved, writable folder.

### Privilege model

The explorer never requests elevation and never attempts to bypass UAC, policy restrictions or ACLs. Some collectors may return *Unavailable*, *Failed*, *Access denied* or *No records* when executed as a standard user. If authorized to inspect higher-privilege settings, an administrator may independently choose to start an elevated session. This changes what is observable; it does not make the explorer a security-configuration editor.

### Advanced auditing query repair — 2026-10-28

The installed `auditpol.exe` rejected the previous `/get /subcategory:* /r` query with exit 87 (`0x00000057`, invalid parameter). The collector now uses `/get /category:* /r`. Native error output and the exit code are captured together in Windows PowerShell 5.1, so diagnostics identify invalid parameters, a missing required privilege (exit 1314), or access denied (exit 5), followed by the native message.

The targeted corrected query in the validation session reached the privilege check and returned exit 1314 (`0x00000522`). Successful live audit collection remains unverified. That repair did not change audit policy, request elevation, or change the then-current failed-refresh rule. Record fields and positional CSV interpretation remain unchanged; the source label reflects the corrected command. The later partial-inventory behavior is described below.

Windows PowerShell 5.1 checks passed for sample CSV field/ID/value preservation, empty output, and simulated exit codes 87, 1314 and 5, including captured native error text and restoration of the caller's error preference. The full inventory was not rerun for this repair.

### Fix in 0.1.1 — WinForms splitter initialization

In 0.1.0, the app could terminate during startup with:

`Exception setting "Panel2MinSize": "SplitterDistance must be between Panel1MinSize and Width - Panel2MinSize."`

The minimum widths/heights were set while WinForms was still using the split controls' small, unlaid-out default dimensions. Version 0.1.1 defers those constraints until after the form is shown, sets a valid splitter position first, and skips unattainable minimum sizes on unusually small layouts. Neither the collectors nor the read-only security model changed.

### UI and navigation

- `SecurityExplorer_UI.ps1` contains UI composition, named sections and locked rich-text helpers. Keep it beside `SecurityExplorer.ps1`. Navigation, results, description, evidence/reference, actions, collection status and browsing status have separate containers.
- Description, evidence/reference and collection status use enabled, read-only rich-text boxes. Text wraps within its section and remains selectable and copyable. Automatic URL activation is disabled; source text is assigned as plain text, not interpreted as RTF or HTML.
- Left: security domains with counts; includes an **Other administrative templates** category because ADMX defines much more than security policies.
- Upper-right: virtualized, searchable inventory table.
- Lower-right: detail, definition help text, source and caveats.
- **Collect / refresh inventory** explicitly recollects live values. Search, navigation and row selection use the displayed snapshot. **Displayed results** selects the latest partial inventory or the last complete run, when available; each entry includes its own time and record count. Records from separate runs are never merged.
- A run that finishes with `Failed` or `Read failed` records is published as **PARTIAL inventory**, including those diagnostic records. This also works on the first run. The collection section shows its time, total records (including diagnostics), failed-record count and individual failure messages. A separate completeness indicator remains visible when filtering or changing domains.
- The application retains the latest partial inventory and last complete run separately in memory. A partial refresh does not overwrite the complete snapshot or its original timestamps. The most recent finished run becomes the displayed view; the selector lets the user return to the other retained snapshot.
- **Export JSON** is enabled only for a selected complete run and writes that run's full sanitized inventory, not just filtered rows. Partial GUI export is disabled because the existing export format has no explicit completeness summary. Command-line `-InventoryOnly` behavior and its diagnostic records are unchanged.
- An unexpected exception that interrupts the collection sequence does not publish its unfinished buffer. The previously displayed snapshot and both retained snapshot slots survive; the collection section reports the interruption. If there is no prior snapshot, the application stays empty with export disabled.
- Collection still uses a replacement buffer and fresh registry cache. **Complete run** means the sequence finished without records marked `Failed` or `Read failed`; it does not establish full security coverage or effective protection. `Unavailable`, `Access denied` and `No records` evidence remains explicitly labelled and must be assessed individually.
- One collection runs at a time. Conflicting controls and window closing are disabled while it runs. This increment remains synchronous: long provider calls may block interaction until they return. Background workers, cancellation and timeouts are not implemented.
- GUI collection coordination does not change the command-line `-InventoryOnly` invocation, collector scope, record fields, redaction, or JSON export format. Command-line collection retains its existing diagnostic-record behavior.
- Separate `TableLayoutPanel` rows prevent the left navigation header from hiding the first list items, including on different DPI scaling levels. Actual device-specific display scaling has **not** been tested here.

## Sources and scope

| Collector | Enumerates | Important limitation |
| --- | --- | --- |
| ADMX/ADML | Installed definitions and localized policy names/descriptions from `%windir%\PolicyDefinitions` | Registry presence does not prove policy effectiveness; complex settings not decoded; central-store-only templates are not imported |
| Defender | Preferences and status | Some property arrays and sensitive strings are redacted |
| Firewall/IPsec | ActiveStore profiles/rules | Rule association filters (e.g. ports, app paths, addresses) omitted |
| auditpol | Advanced audit policy by subcategory | Needs sufficient read rights; CSV column positions assumed by `auditpol /r` |
| secedit | Local security database export for securitypolicy and user_rights | Only numeric scalars shown; principal assignments redacted; policy evaluation not implemented |
| BitLocker | Volume encryption and protection state | No recovery keys or key protector details collected |
| TPM/Secure Boot/DeviceGuard | Firmware/hardware security state | CIM and UEFI queries can be inaccessible or unsupported |
| AppLocker | GP-applied effective rule collection modes/counts | Does **not** include CSP-deployed policy or per-rule paths/SIDs |
| Process mitigations | System mitigation object names | Complex flags not decoded in v0.1 |
| SMB | SMB server/client configuration properties | Secrets, arrays and free-form strings withheld |
| Registry indicators | Selected UAC, LSA, SmartScreen, Remote Desktop and VBS flags | Registry evidence only, not effective-state proof |
| MDM | Policy Result CIM class metadata | CSP policy instance values not read; not a complete MDM inventory |
| Certificates | LocalMachine trust store counts | No subjects, thumbprints or private keys |
| Security services | Names, status, start type | Service state != security effectiveness |

**Not collected:** TPM private or endorsement keys, DPAPI material, credentials, protected LSASS process memory, private certificates, BitLocker recovery information, Defender exclusion paths, raw AppLocker XML rules, raw effective GPO reports, complete MDM payloads, and arbitrary registry sweeps. The explorer does not claim to enumerate undocumented firmware controls or every security setting Microsoft or third-party products might define.

## Interpretation

- **Definition found**: a policy description exists, but its runtime/configured state is not established.
- **Registry value present/absent**: a known registry value was/was not observed, not a verified effective policy state.
- **Complex / undetermined**: the ADMX definition cannot be represented by a single directly readable registry value.
- **Observed**: the particular source reported a value, sometimes configuration, sometimes runtime.
- **Unavailable / Failed**: the collector did not establish a fact about the security control.
- **Exported**: a configured security-policy entry was found in `secedit`'s database export.

PowerShell cmdlets may differ by Windows build, edition, policy and installed modules. No attempt is made to change machine state; `secedit /export` temporarily writes an `.inf` report under the current user's TEMP folder and deletes it after parsing. JSON export is local-only.

## Source map and contribution

| File | Responsibility |
|---|---|
| [SecurityExplorer.ps1](SecurityExplorer.ps1) | Collectors, record construction, evidence handling, collection coordination, command-line mode, and export. |
| [SecurityExplorer_UI.ps1](SecurityExplorer_UI.ps1) | UI layout, sections, and locked rich-text controls. |
| [Launch-SecurityExplorer.cmd](Launch-SecurityExplorer.cmd) | GUI launcher. |
| [Export-Inventory.cmd](Export-Inventory.cmd) | Command-line inventory/export launcher. |
| [RESEARCH_SOURCES.md](RESEARCH_SOURCES.md) | Existing source references and research notes. |
| [FIX_NOTES.md](FIX_NOTES.md) | Historical startup/layout repair notes. |

For collector changes, follow a record from the Windows source through its
classification, display, and sanitized export. Preserve unavailable and failed
states instead of treating them as empty success. For UI changes, use sample
collectors and check both the normal and minimum layouts.

Reports should identify the affected domain, action, and first error. Keep
machine inventories and private identifiers out of public issues. The repository
contains the tool's source, not a published inventory of a particular machine.

No standalone project license is included. The existing source notice is
preserved without assigning a new copyright holder.

## Limitations and test status

The original package reported static Linux inspections only. This local UI increment passed Windows PowerShell 5.1 syntax and sample-data checks at 1350×840 and 880×560, at the session's current scaling. Checks exercised locked text selection, first-run failure, successful publication, overlap prevention, failed-refresh retention/timestamps/diagnostics, export availability and the existing splitter initialization. All live collectors were replaced with sample functions. Control geometry and native rich-text print renderings were inspected; desktop screenshot capture did not expose the isolated sample window.

**Real collection, permissions, system-provider behavior, registry semantics, other DPI settings and Windows 11 Education compatibility remain unverified.** Report errors with the domain and exact message and keep exported inventories private. The original research and startup-fix reports remain historical source documents; this UI work does not independently validate their runtime claims.

For the preceding sectional UI increment, static contract comparison confirmed 25 existing function bodies, including the collectors, sanitization and export functions, and the `-InventoryOnly` branch were text-identical to the imported version. The subsequent Advanced auditing repair changes only `Collect-Audit` and its source label; the other collectors, record schema, export function and command-line entry branch remain unchanged.

The partial-inventory correction was checked in Windows PowerShell 5.1 using two sample observations and four simulated late collector failures. Checks covered first-run partial publication, filtering without losing partial status, complete/partial switching without mixing records or timestamps, complete-only GUI export availability, overlap prevention, and unexpected interruption with and without a prior snapshot. Layouts passed at 1350×840 and 880×560. No live collectors, elevation, policy changes or full machine inventory were run for this correction. The collectors, record fields, JSON export function and command-line entry branch were preserved.
