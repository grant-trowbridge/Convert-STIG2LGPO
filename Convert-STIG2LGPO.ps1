function Convert-STIG2LGPO {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true,
            Position=0,
            HelpMessage="Path to the STIG archive"
        )]
        [ValidateNotNullOrEmpty()]
        [string]$STIGPath
    )
    Write-Verbose "Expanding `"$STIGPath`"..."
    Expand-Archive -Path $STIGPath -DestinationPath ($STIGPath | Split-Path -Parent)
}