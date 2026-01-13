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

if(-not $LGPOPath)
{
    $LGPOPath = "$PSScriptRoot\STIG2LGPOFile_$(Get-Date -Format 'yyyy-MM-ddTHH-mm-ss-fff')"
}
# For time stamping Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff' (Use colons for verbose output?)
$EXPANDPATH = ($STIGPath | Split-Path -Parent) + '\' + (Get-ChildItem -Path $STIGPath).BaseName
Write-Verbose "Expanding `"$STIGPath`"..."
try
{
    Expand-Archive -Path $STIGPath -DestinationPath $EXPANDPATH -ErrorAction Stop
}
catch
{
    Write-Error $PSItem
}

try
{
    $xmlFile = Get-ChildItem -Path "$EXPANDPATH\*" -Include "*.xml" -Recurse
}
catch
{
    Write-Error $PSItem
}

Write-Verbose "$($xmlFile.FullName)"


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

$groups | Get-Member

foreach ($group in $groups)
{
    if($null -eq ($group.Rule.check.{check-content} | Select-String "Not Applicable")) # pre-flight checks to ignore domain-joined system requirements
    {
        if(($group.Rule.check.{check-content} | Select-String "HKEY_LOCAL_MACHINE"))
        {
            Write-Verbose "HKLM hive discussion in $($group.id): $($group.Rule.title)"
            Write-Host "; $($group.id): $($group.Rule.title)`r`nComputer" -ForegroundColor Magenta
        }
    }
    else
    {
        Write-Verbose "Ignoring $($group.id)"
    }
    
}