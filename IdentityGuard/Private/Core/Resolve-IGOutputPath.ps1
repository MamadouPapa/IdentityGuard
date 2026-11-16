function Resolve-IGOutputPath {
    <#
    .SYNOPSIS
        Resolves the report path: default file name in the current folder, or inside a given folder.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()] [string] $OutputPath
    )

    $defaultName = 'IdentityGuard-Report-{0}.html' -f (Get-Date -Format 'yyyyMMdd-HHmmss')

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path (Get-Location).Path $defaultName
    }
    elseif (Test-Path -LiteralPath $OutputPath -PathType Container) {
        $OutputPath = Join-Path $OutputPath $defaultName
    }

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $parent = Split-Path -Path $fullPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
    $fullPath
}
