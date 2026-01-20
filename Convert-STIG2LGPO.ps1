[CmdletBinding()]
param(
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
    [ValidateNotNullOrEmpty()]
    [string]$LGPOPath
)

function Get-LGPOFileEntry { # Finish Regex to determine Configuration, Registry Key, Value Name, and Action (type)
    param (
        [string]$CheckContent,
        [string]$GroupId,
        [string]$RuleId
    )
    $configuration = $null
    
    if($CheckContent -match 'HKLM\\|HKEY_LOCAL_MACHINE\\') {
        $configuration = 'Computer'
    }
    elseif($CheckContent -match 'HKCU\\|HKEY_CURRENT_USER\\') {
        $configuration = 'User'
    }
    else {
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

    # Extract value name
    $valueName = $null
    if($CheckContent -match 'Value Name:\s*(.+?)(?:\r|\n)') {
        $valueName = $Matches[1].Trim()
    }
    elseif($CheckContent -match '(?:Registry )?Value:\s*(.+?)(?:\r|\n).*?Type:') {
        $valueName = $Matches[1].Trim()
    }

    $action = $null
    $type = $null
    $value = $null

    # Extract registry value type
    if($CheckContent -match 'Type:\s*(REG_\w+)') {
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
    if($CheckContent -match 'Value:\s*0x([0-9a-fA-F]+)\s*\((\d+)\)') { # For decimal value
        $value = $Matches[2]
    }
    elseif($CheckContent -match 'Value:\s*0x([0-9a-fA-F]+)') { # Hex only
        $value = [Convert]::ToInt32($Matches[1], 16)
    }
}

if(-not $LGPOPath) {
    $LGPOPath = "$PSScriptRoot\STIG2LGPOFile_$(Get-Date -Format 'yyyy-MM-ddTHH-mm-ss-fff')"
}
# For time stamping Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff' (Use colons for verbose output?)

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

Write-Verbose "Found $($XmlData.SelectNodes('//xccdf:Group/@id', $nsManager).Count) Group IDs"

# Add logic to identify STIG being processed <Benchmark><title>Microsoft Windows 11 Security Technical Implementation Guide</title><Benchmark>

$groups = $xmlData.SelectNodes('//xccdf:Group', $nsManager)

# Iterate through groups and detect Registry discussions under $groups.Rule.check.{check-content}

$lgpoEntries = @()

foreach($group in $groups) {
    Get-LGPOFileEntry -CheckContent $group.Rule.check.{check-content} -GroupId $group.Group
}

Write-Verbose "Cleaning up."
try {
    Remove-Item -Path $EXPANDPATH -Recurse
}
catch {
    Write-Error $PSItem
    return
}