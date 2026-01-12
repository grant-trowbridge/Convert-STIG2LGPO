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
    $LGPOPath = "$PSScriptRoot\STIG2LGPOFile_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff')"
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
    $XmlFile = Get-ChildItem -Path "$EXPANDPATH\*" -Include "*.xml" -Recurse
}
catch
{
    Write-Error $PSItem
}

Write-Verbose "$($XmlFile.FullName)"

$XmlData = New-Object -TypeName System.Xml.XmlDocument
$XmlData.Load($XmlFile.FullName)

# Need to determine namespace of the Group id elements