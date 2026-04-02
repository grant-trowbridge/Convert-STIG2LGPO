[CmdletBinding()]
param (
    [Parameter(
        Mandatory=$true,
        Position=0,
        HelpMessage="Path to the STIG archive"
    )]
    [ValidateNotNullOrEmpty()]
    [string]$STIGPath,

    [parameter(
        Mandatory=$false,
        Position=1,
        HelpMessage="Path to the destination LGPO text file"
    )]
    [string]$LGPOPath
)

function Get-LGPOFileEntry {
    param (
        [string]$Benchmark,
        [string]$CCI,
        [string]$CheckContent,
        [string]$GroupId,
        [string]$RuleId,
        [String]$Title
    )
    
    # Ignore domain-joined system requirements
    $domainJoinedStrings = @(
        '\s+for\s+standalone\s+or\s+nondomain-joined\s+systems\s+this\s+is\s+Not\s+Applicable'
        '\s+for\s+standalone\s+systems\s+this\s+is\s+NA'
        'If\s+the\s+system\s+is\s+not\s+a\s+member\s+of\s+a\s+domain,\s+this\s+is\s+NA'
    )
    foreach($string in $domainJoinedStrings) {
        if($CheckContent -match $string) {
            Write-Verbose "Ignoring domain-joined requirement $GroupId"
            return $null
        }
    }

    # Ignore optional requirements
    $optionalStrings = 'is\s+not\s+required;\s+this\s+is\s+optional.'
    if($CheckContent -match $optionalStrings) {
        Write-Verbose "Ignoring optional requirement $GroupId"
        return $null
    }

    # Extract configuration
    $configuration = $null

    if($CheckContent -match 'HKLM\\|HKLM|HKEY_LOCAL_MACHINE\\|HKEY_LOCAL_MACHINE') {
        $configuration = 'Computer'
    }
    elseif($CheckContent -match 'HKCU\\|HKCU|HKEY_CURRENT_USER\\|HKEY_CURRENT_USER') {
        $configuration = 'User'
    }
    else {
        Write-Verbose "Ignoring VulnID $GroupID"
        return $null
    }

    # Extract registry key
    $registryKey = $null

    if($CheckContent -match 'HK(?:LM|EY_LOCAL_MACHINE)\\(.+?)(?:\r|\n)') {
        $registryKey = $Matches[1].Trim()
    }
    elseif($CheckContent -match 'HK(?:CU|EY_CURRENT_USER)\\(.+?)(?:\r|\n)') {
        $registryKey = $Matches[1].Trim()
    }
    elseif($CheckContent -match 'Registry Path:\s*\\(.+?)(?:\r|\n)') {
        $registryKey = $Matches[1].Trim()
    }

    # Extract value name
    $valueName = $null

    if($CheckContent -match 'Value Name:\s*(.+?)(?:\r|\n)') {
        $valueName = $Matches[1].Trim()
    }
    elseif($CheckContent -match '(?:Registry )?Value:\s*(.+?)(?:\r|\n).*?Type:') {
        $valueName = $Matches[1].Trim()
    }
    elseif($CheckContent -match '(?s)If\s*the\s*value\s*for\s*"(.+?)"') { # Microsoft Edge STIG quoted pattern
        $valueName = $Matches[1].Trim()
    }
    elseif($CheckContent -match '(?s)If\s*the\s*value\s*for\s*“(.+?)”\s') { # Microsoft Edge STIG non-standard quoted pattern
        $valueName = $Matches[1].Trim()
    }
    elseif($CheckContent -match '(?s)If\s*the\s*Reg_\w+\s*value\s*for\s*"(.+?)"\s*') { # Microsoft Edge quoted pattern w/ Registry value type
        $valueName = $Matches[1].Trim()
    }
    elseif($CheckContent -match '(?s)If\s*the\s*value\s*for\s*(.+?)\s') { # Microsoft Edge STIG unquoted pattern
        $valueName = $Matches[1].Trim()
    }

    $action = $null
    $type = $null
    $value = $null

    # Extract registry value type
    if($CheckContent -match 'Type:\s*(REG_\w+)' -or ($Benchmark -match 'Microsoft Edge' -and ($CheckContent -match 'is\s*not\s*set\s*to\s*"(REG_\w+)' -or $CheckContent -match 'If\s*the\s*(REG_\w+)\s*'))) {
        $type = switch($Matches[1]) {
            'REG_DWORD'     { 'DWORD' }
            'REG_SZ'        { 'SZ' }
            'REG_MULTI_SZ'  { 'MULTISZ' }
            'REG_EXPAND_SZ' { 'EXSZ' }
            'REG_BINARY'    { 'BINARY' }
            default         { $Matches[1] }
        }
    }

    # Extract registry value
    if($registryKey -eq 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -and $valueName -eq 'LegalNoticeText') { # Windows specific banner text pattern
        if($CheckContent -match '(?s)Value:\s*(.+)') {
            $value = $Matches[1].Replace("`n`n", "\r\n")
        }
    }
    elseif($registryKey -eq 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -and $valueName -eq 'LegalNoticeCaption') { # Windows specific banner caption pattern
        if($CheckContent -match '(?s)Value:\s*See message title above.+?"(US.+?Statement)"') {
            $value = $Matches[1].Trim()
        }
    }
    elseif($CheckContent -match 'Value:\s*0x([0-9a-fA-F]+)\s*\((\d+)\)') { # For decimal value
        $value = $Matches[2]
    }
    elseif($CheckContent -match 'Value:\s*0x([0-9a-fA-F]+)') { # Hex only
        $value = [Convert]::ToInt32($Matches[1], 16)
    }
    elseif($CheckContent -match 'Value:\s*(\d+)' -and $type -eq 'DWORD') { # Decimal value
        $value = $Matches[1]
    }
    elseif($CheckContent -match 'Value data:\s*(\d+)' -and $type -eq 'DWORD') { # Value data decimal value
        $value = $Matches[1]
    }
    elseif($CheckContent -match '"REG_\w+\s*=\s*(\d+)"' -and $type -eq 'DWORD') { # Microsoft Edge STIG decimal
        $value = $Matches[1]
    }
    elseif($CheckContent -match 'Value:\s*"(.+?)"') { # Quoted string
        $value = $Matches[1]
    }
    elseif($CheckContent -match 'Value:\s*(\d+)\s+(?:\(.+?\))' -and $type -eq 'SZ') { # Unquoted decimal string w/ amplifying info
        $value = $Matches[1].Trim()
    }
    elseif($CheckContent -match '"REG_\w+\s*=\s*(.+?)"' -and $type -eq 'SZ') { # Microsoft Edge STIG string
        $value = $Matches[1].Trim()
    }
    elseif($CheckContent -match 'Example:\s*(.+?)(?:\r|\n)' -and $type -eq 'SZ' -and $valueName -eq 'ProxySettings' -and $Benchmark -like 'Microsoft Edge*') {
        $value = $Matches[1].Trim()
    }
    elseif($CheckContent -match 'Value:\s*(.+?)(?:\r|\n)' -and $type -in @('SZ', 'EXSZ')) { # Unquoted string
        $value = $Matches[1].Trim()
    }
    elseif($CheckContent -match 'Value:\s*(.+?)(?:\r|\n|$)' -and $type -eq 'MULTISZ') { # Multi-string
        $value = $Matches[1].Replace(' ','\0')
    }

    if($type -and $null -ne $value) { # ADD LOGIC FOR 2ND ACTION
        $action = "${type}:${value}"
    }
    if (-not ($configuration -and $registryKey -and $valueName)) {
        Write-Verbose "Ignoring VulnID $GroupID"
        return $null
    }
    
    # Return PSCustomObject
    return [PSCustomObject]@{
        Title         = $Title
        GroupId       = $GroupId
        RuleId        = $RuleId
        CCI           = $CCI
        Configuration = $configuration
        RegistryKey   = $registryKey
        ValueName     = $valueName
        Action        = $action
    }
}

$EXPANDPATH = ($STIGPath | Split-Path -Parent) + '\' + (Get-ChildItem -Path $STIGPath -ErrorAction Stop).BaseName

Write-Verbose "Expanding `"$STIGPath`"..."
try {
    Expand-Archive -Path $STIGPath -DestinationPath $EXPANDPATH -ErrorAction Stop
}
catch {
    Write-Error $PSItem
    return
}

try {
    $xmlFile = Get-ChildItem -Path "$EXPANDPATH\*" -Include "*.xml" -Recurse
    if($null -eq $xmlFile) {
        Write-Verbose "A STIG xml file was not discovered"
        return
    }
}
catch {
    Write-Error $PSItem
    return
}

Write-Verbose "Found $($xmlFile.FullName)"


# Load XML file
$xmlData = New-Object -TypeName System.Xml.XmlDocument
$xmlData.Load($xmlFile.FullName)


# Creating a NamespaceManager object to access elements in the default namespace
$nsManager = New-Object System.Xml.XmlNamespaceManager($xmlData.NameTable)
$nsManager.AddNamespace("xccdf", $xmlData.DocumentElement.NamespaceURI)

Write-Verbose "Found $($XmlData.SelectNodes('//xccdf:Group/@id', $nsManager).Count) Vuln IDs"

# Add logic to identify STIG being processed <Benchmark><title>Microsoft Windows 11 Security Technical Implementation Guide</title><Benchmark>

$benchmark = $XmlData.SelectNodes('//xccdf:Benchmark',$nsManager)

$groups = $xmlData.SelectNodes('//xccdf:Group', $nsManager)

# Iterate through groups and detect Registry discussions under $groups.Rule.check.{check-content}

$lgpoEntries = @()

foreach($group in $groups) {
    if($group.id -eq 'V-253369'){
        Write-Host "[!] Current VulnID is $($group.id)!" -ForegroundColor Green
    }

    $cCheckContent = $group.Rule.check.{check-content}
    $cGroupId = $group.id
    $cRuleId = $group.Rule.id
    $cRuleTitle = $group.Rule.title
    $cCCI = ($group.Rule.ident | Where-Object {$PSItem.system -eq 'http://cyber.mil/cci'} | Select-Object -ExpandProperty '#text').Trim()

    $lgpoEntry = Get-LGPOFileEntry -Benchmark $($benchmark.title).Trim() -CheckContent $cCheckContent -GroupId $cGroupId -RuleId $cRuleId -Title $cRuleTitle -CCI $cCCI

    if($lgpoEntry) {
        $lgpoEntries += $lgpoEntry
        Write-Verbose "Located LGPO entry"
        Write-Verbose "     Title: $($lgpoEntry.Title)"
        Write-Verbose "     Vuln ID: $($lgpoEntry.GroupId)"
        Write-Verbose "     Rule ID: $($lgpoEntry.RuleId)"
        Write-Verbose "     CCI ID: $($lgpoEntry.CCI)"
        Write-Verbose "     Configuration: $($lgpoEntry.Configuration)"
        Write-Verbose "     Registry Key: $($lgpoEntry.RegistryKey)"
        Write-Verbose "     Value Name: $($lgpoEntry.ValueName)"
        Write-Verbose "     Action: $($lgpoEntry.Action)"
    }
}

$lgpoContent = $null
if($lgpoEntries) {
    for($i = 0; $i -lt $lgpoEntries.Length; $i++) {
        if($i -gt 0){
            $lgpoContent += "`r`n`r`n; Title: $($lgpoEntries[$i].Title)`r`n; Vuln ID: $($lgpoEntries[$i].GroupId)`r`n; Rule ID: $($lgpoEntries[$i].RuleId)`r`n; CCI ID: $($lgpoEntries[$i].CCI)`r`n$($lgpoEntries[$i].Configuration)`r`n$($lgpoEntries[$i].RegistryKey)`r`n$($lgpoEntries[$i].ValueName)`r`n$($lgpoEntries[$i].Action)"
        }
        else { # Add Benchmark logic to list STIG title, version & release number at the beginning 
            $lgpoContent = "; $(($benchmark.title).Trim()) Version $(($benchmark.version).Trim()) $($benchmark.{plain-text} | Where-Object {$PSItem.id -eq 'release-info'} | Select-Object -ExpandProperty '#text')"
            $lgpoContent += "`r`n`r`n`r`n; Title: $($lgpoEntries[$i].Title)`r`n; Vuln ID: $($lgpoEntries[$i].GroupId)`r`n; Rule ID: $($lgpoEntries[$i].RuleId)`r`n; CCI ID: $($lgpoEntries[$i].CCI)`r`n$($lgpoEntries[$i].Configuration)`r`n$($lgpoEntries[$i].RegistryKey)`r`n$($lgpoEntries[$i].ValueName)`r`n$($lgpoEntries[$i].Action)"
        }
    }
}

if($null -ne $lgpoContent) {
    if($LGPOPath) {
        try {
            Write-Verbose "Writing LGPO content to `"$LGPOPath`"."
            Write-Output $lgpoContent | Out-File -FilePath $LGPOPath
        }
        catch {
            Write-Error $PSItem
            return
        }
    }
    else{
        $LGPOPath = "$PSScriptRoot\STIG2LGPOFile_$(Get-Date -Format 'yyyy-MM-ddTHH-mm-ss-fff').txt"
        Write-Verbose "Writing LGPO content to `"$LGPOPath`"."
        try {
            Write-Output $lgpoContent | Out-File -FilePath $LGPOPath
        }
        catch {
            Write-Error $PSItem
            return
        }
    }
}

Write-Verbose "Cleaning up."
try {
    Remove-Item -Path $EXPANDPATH -Recurse
}
catch {
    Write-Error $PSItem
    return
}