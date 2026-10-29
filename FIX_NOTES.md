# Security Explorer 0.1.1 — Startup repair

## User-reported failure

`Exception setting "Panel2MinSize": "SplitterDistance must be between Panel1MinSize and Width - Panel2MinSize."`

## Root cause

The GUI assigned 430-pixel and 120-pixel minimum second-panel sizes before WinForms performed its initial layout. At that point, SplitContainer had its initial, small design-time dimensions, so the requested minimum could not fit. Both the main vertical and nested horizontal split controls were affected.

## Fix

- Removed eager `Panel1MinSize` / `Panel2MinSize` assignments for both split controls.
- Added `Initialize-SecuritySplit` invoked on `Form.Shown` after layout.
- Establishes an in-range splitter distance before applying intended panel constraints.
- Checks actual available width/height; retains default constraints if desired sizes do not fit.
- If layout fails for an unforeseen reason, writes a debug warning and still attempts the read-only inventory.
- No changes to security collectors, redaction, privilege requirements, registry, or policy.

## Validation limits

Package assembly, ZIP integrity and static source assertions were checked in Linux. Windows PowerShell 5.1 and the WinForms GUI could not be executed here. Report further messages with the version and line number.
