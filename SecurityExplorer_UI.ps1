# UI-only section builders. No inventory or configuration commands run here.
function New-LockedRichBox([string]$Name, [bool]$Wrap = $true) {
    $box = New-Object System.Windows.Forms.RichTextBox
    $box.Name = $Name; $box.Dock = 'Fill'
    $box.ReadOnly = $true; $box.Enabled = $true; $box.DetectUrls = $false
    $box.WordWrap = $Wrap; $box.HideSelection = $false
    $box.AcceptsTab = $false; $box.ShortcutsEnabled = $true
    $box.ScrollBars = $(if ($Wrap) { 'Vertical' } else { 'Both' })
    $box.BackColor = [System.Drawing.SystemColors]::Window
    $box.BorderStyle = 'FixedSingle'
    return $box
}
function Set-SectionText($Box, [string]$Heading, [string]$Body) {
    $Box.Clear()
    $font = New-Object System.Drawing.Font($Box.Font, [System.Drawing.FontStyle]::Bold)
    try {
        $Box.SelectionFont = $font
        $Box.AppendText($Heading + [Environment]::NewLine)
        $Box.SelectionFont = $Box.Font
        $Box.AppendText($Body)
        $Box.Select(0,0); $Box.ScrollToCaret()
    } finally { $font.Dispose() }
}
function New-TextSection([string]$Name, [string]$Title, [bool]$Wrap = $true) {
    $page = New-Object System.Windows.Forms.TabPage
    $page.Name = $Name; $page.Text = $Title
    $page.Padding = New-Object System.Windows.Forms.Padding(3)
    $box = New-LockedRichBox ($Name + 'Text') $Wrap
    $page.Controls.Add($box); $page.Tag = $box
    return $page
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Security Explorer 0.1.1 | Read-only Windows security inventory'
$form.StartPosition = 'CenterScreen'
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
$form.Font = [System.Drawing.Font]::new('Segoe UI', 9)
$form.AutoScaleDimensions = $form.CurrentAutoScaleDimensions
$form.Size = [System.Drawing.Size]::new(1350, 840)
$form.MinimumSize = [System.Drawing.Size]::new(880, 560)
$form.Add_FormClosing({ param($sender, $eventArgs) if ($script:Busy) { $eventArgs.Cancel = $true } })
$script:UiForm = $form
$rootLayout = New-Object System.Windows.Forms.TableLayoutPanel
$rootLayout.Dock = 'Fill'
$rootLayout.ColumnCount = 1; $rootLayout.RowCount = 3
[void]$rootLayout.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,110.0))
[void]$rootLayout.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Percent,100.0))
[void]$rootLayout.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,26.0))
$form.Controls.Add($rootLayout)

$top = New-Object System.Windows.Forms.TableLayoutPanel
$top.Dock = 'Top'; $top.Height = 106; $top.ColumnCount = 4; $top.RowCount = 3
$top.Padding = [System.Windows.Forms.Padding]::new(10,8,10,5)
$top.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
$top.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent,100.0))) | Out-Null
$top.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
$top.ColumnStyles.Add(([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
$top.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,30.0))) | Out-Null
$top.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,27.0))) | Out-Null
$top.RowStyles.Add(([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,30.0))) | Out-Null
$rootLayout.Controls.Add($top,0,0)

$searchLabel = New-Object System.Windows.Forms.Label
$searchLabel.Text = 'Search'; $searchLabel.AutoSize = $true
$searchLabel.Anchor = 'Left'; $top.Controls.Add($searchLabel,0,0)
$search = New-Object System.Windows.Forms.TextBox
$search.Dock = 'Fill'; $search.Margin = [System.Windows.Forms.Padding]::new(8,0,8,0)
$top.Controls.Add($search,1,0)
$refresh = New-Object System.Windows.Forms.Button
$refresh.Text = 'Collect / refresh inventory'; $refresh.AutoSize = $true
$top.Controls.Add($refresh,2,0)
$export = New-Object System.Windows.Forms.Button
$export.Text = 'Export JSON'; $export.AutoSize = $true
$top.Controls.Add($export,3,0)
$legend = New-Object System.Windows.Forms.Label
$legend.Text = 'Read-only  |  Defined != configured != effective  |  Redacted values  |  No elevation bypass'
$legend.AutoSize = $true; $legend.ForeColor = [System.Drawing.Color]::FromArgb(75,85,99)
$legend.Anchor = 'Left'; $top.SetColumnSpan($legend,4); $top.Controls.Add($legend,0,1)

$snapshotSection = New-Object System.Windows.Forms.TableLayoutPanel
$snapshotSection.Name = 'SnapshotSelectionSection'; $snapshotSection.Dock = 'Fill'
$snapshotSection.ColumnCount = 2; $snapshotSection.RowCount = 1
$snapshotSection.Margin = [System.Windows.Forms.Padding]::new(0)
[void]$snapshotSection.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Absolute,120))
[void]$snapshotSection.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent,100))
$snapshotLabel = New-Object System.Windows.Forms.Label
$snapshotLabel.Text = 'Displayed results'; $snapshotLabel.Dock = 'Fill'; $snapshotLabel.TextAlign = 'MiddleLeft'
$snapshotPicker = New-Object System.Windows.Forms.ComboBox
$snapshotPicker.Name = 'SnapshotPicker'; $snapshotPicker.Dock = 'Fill'
$snapshotPicker.DropDownStyle = 'DropDownList'; $snapshotPicker.DisplayMember = 'Label'; $snapshotPicker.Enabled = $false
$snapshotSection.Controls.Add($snapshotLabel,0,0); $snapshotSection.Controls.Add($snapshotPicker,1,0)
$top.SetColumnSpan($snapshotSection,4); $top.Controls.Add($snapshotSection,0,2)

$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = 'Not scanned'; $statusLabel.Spring = $true; $statusLabel.TextAlign = 'MiddleLeft'
[void]$statusStrip.Items.Add($statusLabel)
$snapshotStateLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$snapshotStateLabel.Name = 'SnapshotCompleteness'; $snapshotStateLabel.BorderSides = 'Left'
$snapshotStateLabel.Text = 'Not collected'
[void]$statusStrip.Items.Add($snapshotStateLabel)
$rootLayout.Controls.Add($statusStrip,0,2)
$script:UiStatus = $statusLabel

$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'; $split.Orientation = 'Vertical'
# Panel minimum sizes must be assigned only AFTER initial layout (see Shown handler).
$rootLayout.Controls.Add($split,0,1)

$navPanel = New-Object System.Windows.Forms.TableLayoutPanel
$navPanel.Dock = 'Fill'; $navPanel.ColumnCount = 1; $navPanel.RowCount = 2
[void]$navPanel.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,32.0))
[void]$navPanel.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Percent,100.0))
$split.Panel1.Controls.Add($navPanel)
$navHeader = New-Object System.Windows.Forms.Label
$navHeader.Dock = 'Fill'; $navHeader.Text = '  SECURITY DOMAINS'
$navHeader.TextAlign = 'MiddleLeft'; $navHeader.Font = [System.Drawing.Font]::new('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
$navTree = New-Object System.Windows.Forms.TreeView
$navTree.Dock = 'Fill'; $navTree.HideSelection = $false; $navTree.ShowLines = $false
$navTree.ShowRootLines = $false; $navTree.ShowPlusMinus = $false
$navPanel.Controls.Add($navHeader,0,0)
$navPanel.Controls.Add($navTree,0,1)

$rightSplit = New-Object System.Windows.Forms.SplitContainer
$rightSplit.Dock = 'Fill'; $rightSplit.Orientation = 'Horizontal'
# Horizontal panel minimum sizes are also deferred until the parent is laid out.
$split.Panel2.Controls.Add($rightSplit)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'; $grid.ReadOnly = $true; $grid.VirtualMode = $true
$grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false; $grid.MultiSelect = $false
$grid.SelectionMode = 'FullRowSelect'; $grid.RowHeadersVisible = $false
$grid.BackgroundColor = [System.Drawing.Color]::White
$grid.BorderStyle = 'FixedSingle'
$grid.AutoSizeRowsMode = 'None'
$grid.EnableHeadersVisualStyles = $true
$grid.Columns.Add('Name','Setting / control') | Out-Null
$grid.Columns.Add('State','Evidence state') | Out-Null
$grid.Columns.Add('Value','Value / summary') | Out-Null
$grid.Columns.Add('Scope','Scope') | Out-Null
$grid.Columns.Add('Source','Source') | Out-Null
$grid.Columns[0].Width = 340
$grid.Columns[1].Width = 170
$grid.Columns[2].Width = 260
$grid.Columns[3].Width = 70
$grid.Columns[4].AutoSizeMode = 'Fill'
foreach ($c in $grid.Columns) { $c.SortMode = 'NotSortable' }
$rightSplit.Panel1.Controls.Add($grid)

$detailPanel = New-Object System.Windows.Forms.TableLayoutPanel
$detailPanel.Dock = 'Fill'; $detailPanel.ColumnCount = 1; $detailPanel.RowCount = 2
[void]$detailPanel.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,28.0))
[void]$detailPanel.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Percent,100.0))
$rightSplit.Panel2.Controls.Add($detailPanel)
$detailHeader = New-Object System.Windows.Forms.Label
$detailHeader.Dock = 'Fill'; $detailHeader.Text = '  PROVENANCE / DESCRIPTION'
$detailHeader.TextAlign = 'MiddleLeft'; $detailHeader.Font = [System.Drawing.Font]::new('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
$detailSections = New-Object System.Windows.Forms.TabControl
$detailSections.Name = 'SelectedControlSections'; $detailSections.Dock = 'Fill'
$descriptionPage = New-TextSection 'ControlDescription' 'Description'
$evidencePage = New-TextSection 'ControlEvidence' 'Evidence and reference'
$descriptionBox = $descriptionPage.Tag; $detailBox = $evidencePage.Tag
[void]$detailSections.TabPages.Add($descriptionPage)
[void]$detailSections.TabPages.Add($evidencePage)
$detailPanel.Controls.Add($detailHeader,0,0)
$detailPanel.Controls.Add($detailSections,0,1)


$rootLayout.Name = 'ApplicationFrame'; $top.Name = 'BrowseAndActionSection'
$navPanel.Name = 'DomainNavigationSection'; $grid.Name = 'InventoryResultsSection'
$detailPanel.Name = 'SelectedControlSection'
# A separate collection section preserves freshness/error state while filters change.
$rootLayout.RowCount = 4
$rootLayout.RowStyles[2].SizeType = 'Absolute'; $rootLayout.RowStyles[2].Height = 82
[void]$rootLayout.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::Absolute,26))
$rootLayout.Controls.Remove($statusStrip)
$rootLayout.Controls.Add($statusStrip,0,3)
$collectionBox = New-LockedRichBox 'CollectionStatusSection'
$rootLayout.Controls.Add($collectionBox,0,2)
Set-SectionText $collectionBox 'Collection: not started' 'Use Collect / refresh inventory. Opening the window does not collect live inventory.'
$export.Enabled = $false
$descriptionBox.Text = 'Collect inventory, then select a control.'
