#requires -Version 5.1
<#
Security Explorer 0.1.1 - read-only Windows security policy and state inventory.
Copyright 2026. Provided as editable source. No elevation or remediation.
Run on Windows 11 with Windows PowerShell 5.1 (STA for GUI).
#>
[CmdletBinding()]
param(
    [switch] $InventoryOnly,
    [string] $OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Items = New-Object 'System.Collections.Generic.List[object]'
$script:Started = Get-Date
$script:Busy = $false
$script:UiStatus = $null
$script:UiForm = $null
$script:HasSnapshot = $false
$script:CompletedAt = $null
$script:LastCompleteSnapshot = $null
$script:LatestPartialSnapshot = $null
$script:SelectedSnapshot = $null
$script:SnapshotSelectionBusy = $false
$script:LastCollectionError = ''
$script:CollectionLog = New-Object 'System.Collections.Generic.List[string]'
$script:RegCache = @{}
$script:DocLinks = @{
    ADMX = 'https://learn.microsoft.com/windows/client-management/understanding-admx-backed-policies'
    PolicyCSP = 'https://learn.microsoft.com/windows/client-management/mdm/policy-configuration-service-provider'
    Defender = 'https://learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus'
    Firewall = 'https://learn.microsoft.com/powershell/module/netsecurity/get-netfirewallprofile'
    Audit = 'https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-get'
    SecEdit = 'https://learn.microsoft.com/windows-server/administration/windows-commands/secedit-export'
    AppLocker = 'https://learn.microsoft.com/powershell/module/applocker/get-applockerpolicy'
    Baselines = 'https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10'
}

function Add-ItemRecord {
    param(
        [string] $Category, [string] $Name, [string] $State,
        [string] $Value = '', [string] $Scope = 'Machine',
        [string] $Source = '', [string] $Id = '',
        [string] $Description = '', [string] $Notes = '',
        [string] $Type = 'Observed', [string] $Reference = ''
    )
    $script:Items.Add([pscustomobject][ordered]@{
        Category = $Category; Name = $Name; State = $State; Value = $Value
        Scope = $Scope; Type = $Type; Source = $Source; Id = $Id
        Description = $Description; Notes = $Notes; Reference = $Reference
        CollectedAt = (Get-Date).ToString('o')
    })
}

function Set-ProgressText([string] $Message) {
    if ($null -ne $script:UiStatus) {
        $script:UiStatus.Text = $Message
        if ($script:Busy) {
            $script:CollectionLog.Add($Message)
            Set-SectionText $collectionBox $Message ($script:CollectionLog -join "`r`n")
        }
        if ($null -ne $script:UiForm) {
            $script:UiForm.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
}

function Invoke-Collector([string] $Name, [scriptblock] $Block) {
    Set-ProgressText ("Collecting: " + $Name + '...')
    $before = $script:Items.Count
    try { & $Block }
    catch {
        Add-ItemRecord 'Collection diagnostics' ($Name + ' collection') 'Failed' '' 'Machine' $Name '' `
            'The collection operation could not complete.' $_.Exception.Message 'Diagnostic'
    }
    if ($script:Items.Count -eq $before) {
        Add-ItemRecord 'Collection diagnostics' ($Name + ' collection') 'No records' '' 'Machine' $Name '' `
            'The collector returned no visible entries; do not interpret that as disabled or absent security.' '' 'Diagnostic'
    }
}

function Get-SafeValue([object] $Value, [string] $Name) {
    if ($Name -match '(?i)password|secret|credential|private.?key|recovery.?key|recovery.?password|keyprotector|token|certificate|thumbprint|account.?name|user.?name|sid|sddl|exclusion|path|address|hostname|identity') {
        return '[withheld]'
    }
    if ($null -eq $Value) { return '[null]' }
    if ($Value -is [bool]) { return [string]$Value }
    if ($Value -is [string]) {
        if ($Value.Length -gt 160) { return '[long string withheld]' }
        if ($Value -match '[\r\n]') { return '[multiline string withheld]' }
        if ($Name -notmatch '(?i)version|status|state|mode|action|direction|policy|level|signature|definition|profile|lastupdated|engine|algorithm|enforcement|provider|product|platform|starttype|displayname') {
            return '[string withheld]'
        }
        return $Value
    }
    if ($Value -is [ValueType]) { return [string]$Value }
    if ($Value -is [array]) {
        if ($Value.Count -eq 0) { return '[empty]' }
        $allNumbers = $true
        foreach ($e in $Value) {
            if (-not ($e -is [ValueType]) -or $e -is [datetime]) { $allNumbers = $false; break }
        }
        if ($allNumbers -and $Value.Count -le 16) { return ($Value -join ', ') }
        return ('[array: ' + $Value.Count + ' elements; values withheld]')
    }
    return '[complex value; not exported]'
}

function Add-ObjectReadings {
    param([object]$Object, [string]$Category, [string]$Prefix,
          [string]$Source, [string]$Reference, [string]$IdPrefix='')
    if ($null -eq $Object) { return }
    foreach ($prop in $Object.PSObject.Properties) {
        if ($prop.Name -match '^(PS|Cim|__).*') { continue }
        # Avoid ever rendering user/secret-bearing values. Property names remain discoverable.
        $safe = Get-SafeValue $prop.Value $prop.Name
        Add-ItemRecord $Category ($Prefix + ' / ' + $prop.Name) 'Observed' $safe 'Machine' `
            $Source ($IdPrefix + ':' + $prop.Name) '' `
            'A returned property is not by itself proof of effective enforcement.' 'Runtime' $Reference
    }
}

function Get-PolicyCategory([string] $Name, [string] $Path) {
    $s = ($Name + ' ' + $Path)
    if ($s -match '(?i)defender|antivirus|antimalware|smart.?screen|real.?time.?protection|attack.?surface') { return 'Defender and malware' }
    if ($s -match '(?i)firewall|ipsec|network protection|network security|lanman|smb|dns|tls|ssl|kerberos') { return 'Firewall and network' }
    if ($s -match '(?i)bitlocker|encryption|credential.?guard|secure.?boot|trusted platform|device.?guard|virtualization.?based|vbs') { return 'Encryption and hardware trust' }
    if ($s -match '(?i)applocker|app.?control|code.?integrity|exploit|execution.?prevention|powershell.*script|script.?block|restricted.?admin') { return 'Application control' }
    if ($s -match '(?i)logon|logoff|password|account|credential|hello|lsa|uac|user account|biometric|authentication|lock.?screen') { return 'Accounts and sign-in' }
    if ($s -match '(?i)audit|event.?log|logging|transcription|record.?events') { return 'Audit and logging' }
    if ($s -match '(?i)update|servicing|patch|windowsupdate|wuau') { return 'Updates and servicing' }
    if ($s -match '(?i)remote.?desktop|terminal.?service|rdp|remote.?assistance|winrm') { return 'Remote access' }
    if ($s -match '(?i)privacy|permission|camera|microphone|location|telemetry|app.?privacy') { return 'Privacy and permissions' }
    if ($s -match '(?i)driver|device.?install|usb|removable.?storage|dma|kernel') { return 'Device and driver security' }
    return 'Other administrative templates'
}

function Resolve-Adml([string] $Text, [System.Collections.IDictionary] $Strings) {
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text -match '^\$\(string\.([^\)]+)\)$') {
        $id = $Matches[1]
        if ($Strings.Contains($id)) { return [string]$Strings[$id] }
        return ('[unresolved: ' + $id + ']')
    }
    return $Text
}

function Test-RegistryEvidence([string] $Hive, [string] $Key, [string] $ValueName) {
    if ([string]::IsNullOrWhiteSpace($Key)) { return @('Definition only', '[no direct registry key]') }
    if ([string]::IsNullOrWhiteSpace($ValueName)) { return @('Complex / undetermined', '[no single registry value]') }
    $root = if ($Hive -eq 'User') { 'HKCU:\' } else { 'HKLM:\' }
    $path = $root + $Key.TrimStart('\')
    try {
        if (-not (Test-Path -LiteralPath $path)) { return @('Value absent', '') }
        $rv = Get-ItemProperty -LiteralPath $path -Name $ValueName -ErrorAction Stop
        $prop = $rv.PSObject.Properties[$ValueName]
        if ($null -eq $prop) { return @('Value absent', '') }
        $safe = Get-SafeValue $prop.Value $ValueName
        return @('Registry value present', $safe)
    }
    catch [System.Management.Automation.ItemNotFoundException] { return @('Value absent', '') }
    catch [System.Management.Automation.PSArgumentException] { return @('Value absent', '') }
    catch [System.UnauthorizedAccessException] { return @('Access denied', '') }
    catch { return @('Read failed', $_.Exception.Message) }
}

function Collect-Admx {
    $base = Join-Path $env:windir 'PolicyDefinitions'
    if (-not (Test-Path -LiteralPath $base)) {
        Add-ItemRecord 'Collection diagnostics' 'Local ADMX definitions' 'Not available' '' 'Machine' `
            $base '' 'No local PolicyDefinitions directory found.' '' 'Diagnostic' $script:DocLinks.ADMX
        return
    }
    $files = @(Get-ChildItem -LiteralPath $base -Filter '*.admx' -File -ErrorAction Stop)
    $idx = 0
    foreach ($file in $files) {
        $idx++
        if (($idx % 25) -eq 0) { Set-ProgressText ("Parsing ADMX: $idx / " + $files.Count) }
        try {
            $lang = [System.Globalization.CultureInfo]::CurrentUICulture.Name
            $adml = Join-Path (Join-Path $base $lang) ($file.BaseName + '.adml')
            if (-not (Test-Path -LiteralPath $adml)) {
                $adml = Join-Path (Join-Path $base 'en-US') ($file.BaseName + '.adml')
            }
            $strings = @{}
            if (Test-Path -LiteralPath $adml) {
                [xml]$loc = [System.IO.File]::ReadAllText($adml)
                foreach ($entry in $loc.SelectNodes("//*[local-name()='stringTable']/*[local-name()='string']")) {
                    $id = $entry.GetAttribute('id')
                    if ($id) { $strings[$id] = $entry.InnerText }
                }
            }
            [xml]$xml = [System.IO.File]::ReadAllText($file.FullName)
            foreach ($pol in $xml.SelectNodes("//*[local-name()='policies']/*[local-name()='policy']")) {
                $rawName = $pol.GetAttribute('name')
                $name = Resolve-Adml $pol.GetAttribute('displayName') $strings
                if (-not $name) { $name = $rawName }
                $desc = Resolve-Adml $pol.GetAttribute('explainText') $strings
                $key = $pol.GetAttribute('key')
                $valueName = $pol.GetAttribute('valueName')
                $class = $pol.GetAttribute('class')
                $catRef = ''
                $parent = $pol.SelectSingleNode("*[local-name()='parentCategory']")
                if ($null -ne $parent) { $catRef = $parent.GetAttribute('ref') }
                $category = Get-PolicyCategory $name ($file.BaseName + ' ' + $key + ' ' + $catRef)
                $scopes = if ($class -eq 'Both') { @('Machine','User') } elseif ($class -eq 'User') { @('User') } else { @('Machine') }
                foreach ($scope in $scopes) {
                    $r = Test-RegistryEvidence $scope $key $valueName
                    $regHive = if ($scope -eq 'User') { 'HKCU' } else { 'HKLM' }
                    $id = 'ADMX:' + $file.Name + ':' + $rawName + ':' + $scope
                    $notes = "Definition: $($file.Name); source scope: $class; category ref: $catRef; registry: $regHive\$key"
                    if ($valueName) { $notes += '\' + $valueName }
                    $notes += '. Registry presence does not establish effective policy. Complex ADMX policies require specialized interpretation.'
                    Add-ItemRecord $category $name $r[0] $r[1] $scope ('ADMX/ADML: ' + $file.Name) `
                        $id $desc $notes 'Definition' $script:DocLinks.ADMX
                }
            }
        }
        catch {
            Add-ItemRecord 'Collection diagnostics' ('ADMX parsing: ' + $file.Name) 'Failed' '' 'Machine' `
                $file.FullName '' '' $_.Exception.Message 'Diagnostic' $script:DocLinks.ADMX
        }
    }
    Add-ItemRecord 'Collection diagnostics' 'ADMX files inspected' 'Observed' ([string]$files.Count) `
        'Machine' $base '' 'Number of ADMX files scanned, including files with no policy elements.' '' 'Diagnostic'
}

function Collect-Defender {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { throw 'Defender PowerShell cmdlets not installed.' }
    Add-ObjectReadings (Get-MpPreference -ErrorAction Stop) 'Defender and malware' 'Preferences' `
        'Get-MpPreference' $script:DocLinks.Defender 'DefenderPreference'
    Add-ObjectReadings (Get-MpComputerStatus -ErrorAction Stop) 'Defender and malware' 'Runtime status' `
        'Get-MpComputerStatus' $script:DocLinks.Defender 'DefenderStatus'
}

function Collect-Firewall {
    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { throw 'NetSecurity module not available.' }
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
        Add-ObjectReadings $p 'Firewall and network' ('Firewall profile ' + $p.Name) `
            'Get-NetFirewallProfile -PolicyStore ActiveStore' $script:DocLinks.Firewall ('FirewallProfile:' + $p.Name)
    }
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)) {
        $nm = if ($rule.DisplayName) { [string]$rule.DisplayName } else { [string]$rule.Name }
        Add-ItemRecord 'Firewall and network' ('Firewall rule: ' + $nm) 'Observed' `
            ("Enabled=$($rule.Enabled); Direction=$($rule.Direction); Action=$($rule.Action); Profile=$($rule.Profile)") `
            'Machine' 'Get-NetFirewallRule -PolicyStore ActiveStore' ('FirewallRule:' + $rule.Name) `
            ([string]$rule.Description) `
            'This rule summary omits associated port/address/application filters. ActiveStore is the resultant active firewall policy store.' `
            'Runtime' $script:DocLinks.Firewall
    }
    $cmd = Get-Command Get-NetIPsecRule -ErrorAction SilentlyContinue
    if ($cmd) {
        foreach ($rule in @(Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop)) {
            $nm = if ($rule.DisplayName) { [string]$rule.DisplayName } else { [string]$rule.Name }
            Add-ItemRecord 'Firewall and network' ('IPsec rule: ' + $nm) 'Observed' `
                ("Enabled=$($rule.Enabled); Mode=$($rule.Mode)") 'Machine' 'Get-NetIPsecRule -PolicyStore ActiveStore' `
                ('IPsecRule:' + $rule.Name) '' 'Associated filters and keying details are not exported.' 'Runtime' $script:DocLinks.Firewall
        }
    }
}

function Collect-Audit {
    # Windows PowerShell 5.1 can promote redirected native stderr to a
    # terminating error under Stop, before LASTEXITCODE can be inspected.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $raw = @(& auditpol.exe /get /category:* /r 2>&1)
        $auditExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($auditExit -ne 0) {
        $nativeMessages = @($raw | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message }
            else { [string]$_ }
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $reason = switch ($auditExit) {
            87 { 'Invalid parameter' }
            1314 { 'Required privilege not held' }
            5 { 'Access denied' }
            default { 'Query failed' }
        }
        throw ('auditpol /get /category:* /r: ' + $reason + ' (exit ' + $auditExit + '). ' + ($nativeMessages -join ' '))
    }
    $parsed = @($raw | Where-Object { $_ -is [string] -and $_.Trim() } | ConvertFrom-Csv)
    if ($parsed.Count -eq 0) { throw 'auditpol returned no CSV rows.' }
    foreach ($record in $parsed) {
        $cells = @($record.PSObject.Properties | ForEach-Object { [string]$_.Value })
        if ($cells.Count -lt 5) { continue }
        Add-ItemRecord 'Audit and logging' ('Audit: ' + $cells[2]) 'Observed' $cells[4] 'Machine' `
            'auditpol /get /category:* /r' ('AuditSubcategory:' + $cells[3]) '' `
            'Reported system audit policy; output columns parsed by position from auditpol CSV.' 'Runtime' $script:DocLinks.Audit
    }
}

function Collect-Secedit {
    $stamp = [guid]::NewGuid().ToString('N')
    $file = Join-Path $env:TEMP ('SecurityExplorer-' + $stamp + '.inf')
    $log = Join-Path $env:TEMP ('SecurityExplorer-' + $stamp + '.log')
    try {
        $null = & secedit.exe /export /cfg $file /areas securitypolicy user_rights /log $log /quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('secedit export failed with exit code ' + $LASTEXITCODE) }
        if (-not (Test-Path -LiteralPath $file)) { throw 'No output file created by secedit.' }
        $section = ''
        foreach ($line in [System.IO.File]::ReadAllLines($file,[System.Text.Encoding]::Unicode)) {
            $s = $line.Trim()
            if ($s -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
            if ($s -notmatch '^([^=]+?)\s*=\s*(.*)$') { continue }
            $name = $Matches[1].Trim(); $rawValue = $Matches[2].Trim()
            if ($section -match 'Unicode|Version') { continue }
            # The export contains privilege assignments and potentially security-sensitive identifiers.
            # Show numeric scalar values; redact strings and membership details.
            $val = if ($rawValue -match '^\d+$') { $rawValue } else { '[raw value withheld]' }
            Add-ItemRecord 'Local security policy' ($section + ' / ' + $name) 'Exported' $val `
                'Machine' 'secedit /export (local security database)' ('SecEdit:' + $section + ':' + $name) '' `
                'Local security template snapshot. Not proof that every setting is effectively enforced. Non-numeric contents withheld.' `
                'Configured' $script:DocLinks.SecEdit
        }
    }
    finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    }
}

function Collect-BitLocker {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { throw 'BitLocker PowerShell cmdlet not installed.' }
    foreach ($v in @(Get-BitLockerVolume -ErrorAction Stop)) {
        $label = if ($v.MountPoint) { [string]$v.MountPoint } else { '[volume without mount point]' }
        foreach ($p in @('VolumeStatus','ProtectionStatus','EncryptionPercentage','EncryptionMethod','LockStatus')) {
            Add-ItemRecord 'Encryption and hardware trust' ("BitLocker $label / $p") 'Observed' `
                (Get-SafeValue $v.$p $p) 'Machine' 'Get-BitLockerVolume' ('BitLocker:' + $label + ':' + $p) '' `
                'Recovery keys, protectors, and volume identifiers are deliberately not collected.' 'Runtime'
        }
    }
}

function Collect-HardwareSecurity {
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            Add-ObjectReadings (Get-Tpm -ErrorAction Stop) 'Encryption and hardware trust' 'TPM' 'Get-Tpm' `
                'https://learn.microsoft.com/powershell/module/trustedplatformmodule/get-tpm' 'TPM'
        } catch {
            Add-ItemRecord 'Encryption and hardware trust' 'TPM inventory' 'Unavailable' '' 'Machine' 'Get-Tpm' '' '' $_.Exception.Message 'Diagnostic'
        }
    }
    try {
        $result = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-ItemRecord 'Encryption and hardware trust' 'Secure Boot' 'Observed' ([string]$result) 'Machine' `
            'Confirm-SecureBootUEFI' 'SecureBoot' 'UEFI Secure Boot state as reported by firmware/Windows.' '' 'Runtime'
    }
    catch {
        Add-ItemRecord 'Encryption and hardware trust' 'Secure Boot' 'Unavailable' '' 'Machine' `
            'Confirm-SecureBootUEFI' 'SecureBoot' '' $_.Exception.Message 'Diagnostic'
    }
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        Add-ObjectReadings $dg 'Encryption and hardware trust' 'Device Guard / VBS' 'Win32_DeviceGuard CIM' `
            'https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure' 'DeviceGuard'
    } catch {
        Add-ItemRecord 'Encryption and hardware trust' 'Device Guard / VBS' 'Unavailable' '' 'Machine' `
            'Win32_DeviceGuard CIM' 'DeviceGuard' '' $_.Exception.Message 'Diagnostic'
    }
}

function Collect-AppControl {
    if (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue) {
        $xmlText = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
        [xml]$doc = [string]$xmlText
        foreach ($node in $doc.SelectNodes("//*[local-name()='RuleCollection']")) {
            $type = $node.GetAttribute('Type')
            $mode = $node.GetAttribute('EnforcementMode')
            $count = @($node.SelectNodes('*')).Count
            Add-ItemRecord 'Application control' ('AppLocker collection: ' + $type) 'Observed' `
                ("Mode=$mode; RuleCount=$count") 'Machine' 'Get-AppLockerPolicy -Effective -Xml' ('AppLocker:' + $type) '' `
                'GPO-deployed policy only. AppLocker CSP policies are not included. Rule paths and user SIDs are withheld.' `
                'Runtime' $script:DocLinks.AppLocker
        }
    } else { throw 'AppLocker cmdlets not installed.' }
}

function Collect-ExploitProtection {
    if (-not (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue)) { throw 'ProcessMitigations module not installed.' }
    $result = Get-ProcessMitigation -System -ErrorAction Stop
    foreach ($prop in $result.PSObject.Properties) {
        if ($prop.Name -match '^PS') { continue }
        $value = $prop.Value
        $summary = if ($null -eq $value) { '[null]' } elseif ($value -is [ValueType]) { [string]$value } `
            else { '[compound mitigation configuration; not flattened]' }
        Add-ItemRecord 'Application control' ('System mitigation / ' + $prop.Name) 'Observed' $summary `
            'Machine' 'Get-ProcessMitigation -System' ('Mitigation:' + $prop.Name) '' `
            'Complex mitigation flags require a typed decoder; raw objects not exported.' 'Runtime'
    }
}

function Collect-SMB {
    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Add-ObjectReadings (Get-SmbServerConfiguration -ErrorAction Stop) 'Firewall and network' `
            'SMB server configuration' 'Get-SmbServerConfiguration' '' 'SMBServer'
    }
    if (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        Add-ObjectReadings (Get-SmbClientConfiguration -ErrorAction Stop) 'Firewall and network' `
            'SMB client configuration' 'Get-SmbClientConfiguration' '' 'SMBClient'
    }
}

function Collect-WindowsPolicies {
    $regs = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA','Accounts and sign-in','UAC enabled configuration'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','ConsentPromptBehaviorAdmin','Accounts and sign-in','UAC administrator consent policy'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','PromptOnSecureDesktop','Accounts and sign-in','UAC secure desktop policy'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL','Accounts and sign-in','LSA protection configuration'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel','Accounts and sign-in','LAN Manager authentication compatibility'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System','EnableSmartScreen','Defender and malware','SmartScreen policy'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','Remote access','Remote Desktop connections'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard','EnableVirtualizationBasedSecurity','Encryption and hardware trust','VBS configuration'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity','Enabled','Encryption and hardware trust','Memory integrity configured flag')
    )
    foreach ($info in $regs) {
        $path, $name, $category, $desc = $info
        $scope = 'Machine'
        $value = ''
        $state = 'Value absent'
        try {
            $o = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
            $p = $o.PSObject.Properties[$name]
            if ($null -ne $p) { $state = 'Registry value present'; $value = Get-SafeValue $p.Value $name }
        } catch [System.Management.Automation.ItemNotFoundException] { } `
          catch [System.Management.Automation.PSArgumentException] { } `
          catch { $state = 'Unavailable'; $value = $_.Exception.Message }
        Add-ItemRecord $category $desc $state $value $scope 'Registry: curated security configuration' `
            ($path + '\' + $name) '' `
            'Configuration value, not independently verified as effective enforcement.' 'Configured'
    }
}

function Collect-MDMDefinitions {
    try {
        $classes = @(Get-CimClass -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_Policy_Result01_*' -ErrorAction Stop)
        if ($classes.Count -eq 0) {
            Add-ItemRecord 'MDM policy visibility' 'MDM Policy Result classes' 'No matching classes' '' 'Machine' `
                'root/cimv2/mdm/dmmap' '' 'This does not prove absence of MDM policy.' '' 'Diagnostic' $script:DocLinks.PolicyCSP
        }
        foreach ($cls in $classes) {
            Add-ItemRecord 'MDM policy visibility' $cls.CimClassName 'Definition found' '[instance values not read]' `
                'Machine' 'Get-CimClass (metadata only)' ('MDM:' + $cls.CimClassName) '' `
                'Class metadata enumeration only. Does not provide effective MDM policy values; CSP and provisioning sources may differ.' `
                'Definition' $script:DocLinks.PolicyCSP
        }
    } catch {
        Add-ItemRecord 'MDM policy visibility' 'MDM class discovery' 'Unavailable' '' 'Machine' `
            'Get-CimClass root/cimv2/mdm/dmmap' '' '' $_.Exception.Message 'Diagnostic' $script:DocLinks.PolicyCSP
    }
}

function Collect-CertificateStoreCounts {
    foreach ($store in @('Root','CA','TrustedPublisher','Disallowed')) {
        try {
            $count = @(Get-ChildItem -Path ('Cert:\LocalMachine\' + $store) -ErrorAction Stop).Count
            Add-ItemRecord 'Encryption and hardware trust' ('Certificate store / ' + $store) 'Observed' `
                ([string]$count + ' certificates') 'Machine' 'Cert:\LocalMachine (counts only)' ('CertStore:' + $store) '' `
                'Counts only; subjects, private keys, and thumbprints are not collected.' 'Runtime'
        } catch {
            Add-ItemRecord 'Encryption and hardware trust' ('Certificate store / ' + $store) 'Unavailable' `
                '' 'Machine' 'Cert:\LocalMachine' ('CertStore:' + $store) '' $_.Exception.Message 'Diagnostic'
        }
    }
}

function Collect-SecurityServices {
    foreach ($service in @('WinDefend','WdNisSvc','mpssvc','BFE','wscsvc','SecurityHealthService','WinRM','EventLog')) {
        try {
            $s = Get-Service -Name $service -ErrorAction Stop
            Add-ItemRecord 'Security services' $service 'Observed' ("Status=$($s.Status); StartType=$($s.StartType)") `
                'Machine' 'Get-Service' ('Service:' + $service) ([string]$s.DisplayName) `
                'Service runtime/state is not equivalent to complete security capability.' 'Runtime'
        } catch {
            Add-ItemRecord 'Security services' $service 'Unavailable' '' 'Machine' 'Get-Service' `
                ('Service:' + $service) '' $_.Exception.Message 'Diagnostic'
        }
    }
}

function Collect-All {
    $script:Items.Clear()
    $script:Started = Get-Date
    Invoke-Collector 'Administrative Templates (ADMX/ADML)' { Collect-Admx }
    Invoke-Collector 'Defender preferences and runtime' { Collect-Defender }
    Invoke-Collector 'Firewall and IPsec active policies' { Collect-Firewall }
    Invoke-Collector 'Advanced auditing' { Collect-Audit }
    Invoke-Collector 'Local Security Policy' { Collect-Secedit }
    Invoke-Collector 'BitLocker volume status' { Collect-BitLocker }
    Invoke-Collector 'TPM, Secure Boot and Device Guard' { Collect-HardwareSecurity }
    Invoke-Collector 'AppLocker GPO policy' { Collect-AppControl }
    Invoke-Collector 'System exploit protections' { Collect-ExploitProtection }
    Invoke-Collector 'SMB configuration' { Collect-SMB }
    Invoke-Collector 'Curated registry indicators' { Collect-WindowsPolicies }
    Invoke-Collector 'MDM CSP class metadata' { Collect-MDMDefinitions }
    Invoke-Collector 'Certificate store counts' { Collect-CertificateStoreCounts }
    Invoke-Collector 'Security service status' { Collect-SecurityServices }
    Set-ProgressText ("Completed: " + $script:Items.Count + ' records')
}

function Export-Inventory([string] $FilePath) {
    # JSON is restricted to the sanitized fields generated by Add-ItemRecord.
    $result = [ordered]@{
        Tool = 'Security Explorer'; Version = '0.1.1'; Mode = 'read-only'
        ComputerOS = [Environment]::OSVersion.VersionString
        StartedAt = $script:Started.ToString('o')
        ExportedAt = (Get-Date).ToString('o')
        RecordCount = $script:Items.Count
        Warning = 'Contains policy configuration and machine security posture; handle as sensitive. Values are redacted by default.'
        Records = @($script:Items.ToArray())
    }
    $json = ConvertTo-Json -InputObject $result -Depth 6
    [System.IO.File]::WriteAllText($FilePath, $json, ([System.Text.UTF8Encoding]::new($false)))
}

if ($InventoryOnly) {
    Collect-All
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path (Get-Location).Path 'SecurityExplorer-Inventory.json'
    }
    Export-Inventory ([System.IO.Path]::GetFullPath($OutputPath))
    Write-Output ("Saved $($script:Items.Count) records to $OutputPath")
    return
}

. (Join-Path $PSScriptRoot 'SecurityExplorer_UI.ps1')

$script:Visible = New-Object 'System.Collections.Generic.List[object]'
$script:ChosenCategory = 'All domains'
$grid.add_CellValueNeeded({
    param($sender,$e)
    if ($e.RowIndex -lt 0 -or $e.RowIndex -ge $script:Visible.Count) { return }
    $r = $script:Visible[$e.RowIndex]
    switch ($e.ColumnIndex) {
        0 { $e.Value = $r.Name }
        1 { $e.Value = $r.State }
        2 { $e.Value = $r.Value }
        3 { $e.Value = $r.Scope }
        4 { $e.Value = $r.Source }
    }
})

function Update-Details {
    if ($grid.SelectedRows.Count -eq 0) { $detailBox.Clear(); $descriptionBox.Clear(); return }
    $i = $grid.SelectedRows[0].Index
    if ($i -lt 0 -or $i -ge $script:Visible.Count) { $detailBox.Clear(); $descriptionBox.Clear(); return }
    $r = $script:Visible[$i]
    Set-SectionText $descriptionBox ([string]$r.Name) ([string]$r.Description)
    $detailBox.Text = @(
        'CONTROL: ' + $r.Name
        'DOMAIN: ' + $r.Category
        'EVIDENCE: ' + $r.State
        'VALUE: ' + $r.Value
        'SCOPE: ' + $r.Scope
        'RECORD TYPE: ' + $r.Type
        'SOURCE: ' + $r.Source
        'IDENTITY: ' + $r.Id
        'TIME: ' + $r.CollectedAt
        ''
        'METHOD / LIMITATIONS:'
        $r.Notes
        ''
        'REFERENCE:'
        $r.Reference
    ) -join [Environment]::NewLine
}
$grid.add_SelectionChanged({ Update-Details })

function Apply-Filter {
    $script:Visible.Clear()
    $find = $search.Text.Trim()
    foreach ($rec in $script:Items) {
        if ($script:ChosenCategory -ne 'All domains' -and $rec.Category -ne $script:ChosenCategory) { continue }
        if ($find) {
            $combined = $rec.Name + ' ' + $rec.Category + ' ' + $rec.Id + ' ' + $rec.Source + ' ' + $rec.Description + ' ' + $rec.State + ' ' + $rec.Value
            if ($combined.IndexOf($find,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        }
        $script:Visible.Add($rec)
    }
    $grid.RowCount = 0
    $grid.RowCount = $script:Visible.Count
    if ($grid.RowCount -gt 0) { $grid.ClearSelection(); $grid.Rows[0].Selected = $true; $grid.CurrentCell = $grid.Rows[0].Cells[0] }
    else { $detailBox.Clear(); $descriptionBox.Clear() }
    $statusLabel.Text = ("Shown: $($script:Visible.Count) / $($script:Items.Count) records | " + `
        $script:ChosenCategory + ' | Read-only')
    Update-SnapshotCompleteness
}

function Build-Navigation {
    $script:ChosenCategory = 'All domains'
    $navTree.BeginUpdate()
    try {
        $navTree.Nodes.Clear()
        $all = $navTree.Nodes.Add('All domains (' + $script:Items.Count + ')')
        $all.Tag = 'All domains'
        foreach ($grp in @($script:Items | Group-Object Category | Sort-Object Name)) {
            $node = $navTree.Nodes.Add($grp.Name + ' (' + $grp.Count + ')')
            $node.Tag = $grp.Name
        }
        $navTree.SelectedNode = $all
    } finally { $navTree.EndUpdate() }
}
$navTree.add_AfterSelect({
    if ($null -ne $navTree.SelectedNode) {
        $script:ChosenCategory = [string]$navTree.SelectedNode.Tag
        Apply-Filter
    }
})
$search.add_TextChanged({ if (-not $script:Busy) { Apply-Filter } })

function Update-SnapshotCompleteness {
    if ($null -eq $script:SelectedSnapshot) {
        $snapshotStateLabel.Text = 'Not collected'
    } elseif ($script:SelectedSnapshot.IsPartial) {
        $snapshotStateLabel.Text = 'PARTIAL inventory | ' + $script:SelectedSnapshot.FailedRecords.Count + ' failed records'
    } else {
        $snapshotStateLabel.Text = 'Complete run | Review evidence limits'
    }
    $export.Enabled = (!$script:Busy -and $null -ne $script:SelectedSnapshot -and !$script:SelectedSnapshot.IsPartial)
}
function Update-SnapshotChoices {
    $script:SnapshotSelectionBusy = $true
    try {
        $snapshotPicker.Items.Clear()
        foreach ($snapshot in @($script:LatestPartialSnapshot, $script:LastCompleteSnapshot)) {
            if ($null -eq $snapshot) { continue }
            $kind = $(if ($snapshot.IsPartial) { 'Latest partial inventory' } else { 'Last complete run' })
            $choice = [pscustomobject]@{
                Label = $kind + ' | ' + $snapshot.FinishedAt.ToString('yyyy-MM-dd HH:mm:ss zzz') + ' | ' + $snapshot.Items.Count + ' records'
                Snapshot = $snapshot
            }
            [void]$snapshotPicker.Items.Add($choice)
            if ([object]::ReferenceEquals($snapshot, $script:SelectedSnapshot)) { $snapshotPicker.SelectedItem = $choice }
        }
    } finally { $script:SnapshotSelectionBusy = $false }
    $snapshotPicker.Enabled = (!$script:Busy -and $snapshotPicker.Items.Count -gt 0)
}
function Write-SnapshotSummary {
    $snapshot = $script:SelectedSnapshot
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $snapshot) {
        $heading = 'No inventory published'
        $lines.Add('No prior snapshot is available.')
    } else {
        $heading = $(if ($snapshot.IsPartial) { 'PARTIAL inventory - collector failures retained' } else { 'Complete collection run - review per-record evidence limits' })
        $lines.Add('Collected: ' + $snapshot.FinishedAt.ToString('yyyy-MM-dd HH:mm:ss zzz'))
        $lines.Add('Total records (including diagnostics): ' + $snapshot.Items.Count + '; failed records: ' + $snapshot.FailedRecords.Count)
        if ($snapshot.IsPartial) { $lines.Add('Partial export is disabled. These records establish only what their individual sources reported.') }
        else { $lines.Add('A complete run does not establish that every security control is effective or observable.') }
        foreach ($record in $snapshot.FailedRecords) { $lines.Add($record.Name + ': ' + $record.Notes) }
    }
    if ($script:LastCollectionError) {
        $heading = 'Collection interrupted - previous display retained'
        $lines.Add('Latest attempt failed: ' + $script:LastCollectionError)
        foreach ($line in $script:CollectionLog) { $lines.Add($line) }
    }
    Set-SectionText $collectionBox $heading ($lines -join "`r`n")
    Update-SnapshotCompleteness
}
function Show-SecuritySnapshot($Snapshot) {
    $script:SelectedSnapshot = $Snapshot
    $script:Items = $Snapshot.Items; $script:Started = $Snapshot.Started
    $script:RegCache = $Snapshot.RegCache
    $script:HasSnapshot = $true; $script:CompletedAt = $Snapshot.FinishedAt
    Build-Navigation
    Apply-Filter
    Write-SnapshotSummary
}
$snapshotPicker.add_SelectedIndexChanged({
    if ($script:Busy -or $script:SnapshotSelectionBusy -or $null -eq $snapshotPicker.SelectedItem) { return }
    Show-SecuritySnapshot $snapshotPicker.SelectedItem.Snapshot
})

function Refresh-Gui {
    if ($script:Busy) { return }
    $previousItems = $script:Items; $previousStarted = $script:Started
    $previousCache = $script:RegCache
    $previousSelected = $script:SelectedSnapshot
    $previousComplete = $script:LastCompleteSnapshot; $previousPartial = $script:LatestPartialSnapshot
    $script:Busy = $true
    $refresh.Enabled = $false; $export.Enabled = $false
    $search.Enabled = $false; $navTree.Enabled = $false; $grid.Enabled = $false
    $snapshotPicker.Enabled = $false
    $form.ControlBox = $false
    $script:CollectionLog.Clear()
    try {
        $script:Items = New-Object 'System.Collections.Generic.List[object]'
        $script:RegCache = @{}
        Collect-All
        $failed = @($script:Items | Where-Object { $_.State -eq 'Failed' -or $_.State -eq 'Read failed' })
        $snapshot = [pscustomobject]@{
            Items = $script:Items; Started = $script:Started; FinishedAt = Get-Date
            RegCache = $script:RegCache; IsPartial = ($failed.Count -gt 0); FailedRecords = $failed
        }
        if ($snapshot.IsPartial) { $script:LatestPartialSnapshot = $snapshot }
        else { $script:LastCompleteSnapshot = $snapshot }
        $script:LastCollectionError = ''
        Show-SecuritySnapshot $snapshot
        Update-SnapshotChoices
    } catch {
        $message = $_.Exception.Message
        $script:Items = $previousItems; $script:Started = $previousStarted; $script:RegCache = $previousCache
        $script:SelectedSnapshot = $previousSelected
        $script:LastCompleteSnapshot = $previousComplete; $script:LatestPartialSnapshot = $previousPartial
        $script:HasSnapshot = ($null -ne $previousSelected)
        $script:CompletedAt = $(if ($script:HasSnapshot) { $previousSelected.FinishedAt } else { $null })
        $script:LastCollectionError = $message
        Build-Navigation
        Apply-Filter
        Update-SnapshotChoices
        Write-SnapshotSummary
    } finally {
        $refresh.Enabled = $true
        $search.Enabled = $true; $navTree.Enabled = $true; $grid.Enabled = $true
        $form.ControlBox = $true; $script:Busy = $false
        $snapshotPicker.Enabled = ($snapshotPicker.Items.Count -gt 0)
        Update-SnapshotCompleteness
    }
}
$refresh.add_Click({ Refresh-Gui })
$export.add_Click({
    if ($script:Busy -or $null -eq $script:SelectedSnapshot -or $script:SelectedSnapshot.IsPartial) { return }
    $save = New-Object System.Windows.Forms.SaveFileDialog
    $save.Filter = 'JSON inventory (*.json)|*.json'
    $save.FileName = 'SecurityExplorer-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'
    $save.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    $save.OverwritePrompt = $true
    if ($save.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            Export-Inventory $save.FileName
            [System.Windows.Forms.MessageBox]::Show(
                'Exported sanitized security inventory. The report still contains security posture information; store it carefully.',
                'Export complete', 'OK', 'Information') | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Export failed','OK','Error') | Out-Null
        }
    }
})
# SplitContainer starts with a small default Size before its parent performs layout.
# Applying Panel2MinSize at construction time can therefore throw:
# 'SplitterDistance must be between Panel1MinSize and Width - Panel2MinSize.'
# Instead, once Shown has laid out the real client area, put the splitter at a
# valid position FIRST and only then enforce the preferred minimum sizes.
function Initialize-SecuritySplit {
    param(
        [System.Windows.Forms.SplitContainer] $Container,
        [int] $FirstMin,
        [int] $SecondMin,
        [double] $FirstFraction,
        [int] $FirstCap = 0
    )

    $dimension = if ($Container.Orientation -eq [System.Windows.Forms.Orientation]::Vertical) {
        [int] $Container.ClientSize.Width
    } else {
        [int] $Container.ClientSize.Height
    }
    $usable = $dimension - [int] $Container.SplitterWidth
    $oldFirstMin = [int] $Container.Panel1MinSize
    $oldSecondMin = [int] $Container.Panel2MinSize
    if ($usable -lt ($oldFirstMin + $oldSecondMin)) { return }

    $desired = [int] [math]::Round($usable * $FirstFraction)
    if ($FirstCap -gt 0) { $desired = [math]::Min($desired, $FirstCap) }

    if ($usable -ge ($FirstMin + $SecondMin)) {
        # The container is large enough for both intended constraints.
        $desired = [math]::Max($FirstMin, [math]::Min($desired, $usable - $SecondMin))
        $Container.SplitterDistance = $desired
        $Container.Panel1MinSize = $FirstMin
        $Container.Panel2MinSize = $SecondMin
    } else {
        # Tiny screen / unusual display scaling: keep WinForms' default
        # minimums rather than assigning physically impossible constraints.
        $desired = [math]::Max($oldFirstMin, [math]::Min($desired, $usable - $oldSecondMin))
        $Container.SplitterDistance = $desired
    }
}

$form.add_Shown({
    try {
        # Parent first; the nested right-side split depends on its final size.
        $form.PerformLayout()
        $rootLayout.PerformLayout()
        $split.PerformLayout()
        Initialize-SecuritySplit -Container $split -FirstMin 165 -SecondMin 430 -FirstFraction 0.22 -FirstCap 265
        $rightSplit.PerformLayout()
        Initialize-SecuritySplit -Container $rightSplit -FirstMin 140 -SecondMin 120 -FirstFraction 0.64
    } catch {
        # A display-layout problem must never prevent a read-only scan.
        [System.Diagnostics.Debug]::WriteLine('Security Explorer layout warning: ' + $_.Exception.Message)
    }
    $statusLabel.Text = 'Not collected | Read-only'
})

[void][System.Windows.Forms.Application]::Run($form)
