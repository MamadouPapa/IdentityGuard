# HTML primitives. Every value coming from directory data MUST go through ConvertTo-IGHtml.

$script:IGSeverityCssClass = @{
    'Critique' = 'sev-critical'
    'Élevée'   = 'sev-high'
    'Moyenne'  = 'sev-medium'
    'Faible'   = 'sev-low'
    'Info'     = 'sev-info'
}

function ConvertTo-IGHtml {
    <#
    .SYNOPSIS
        HTML-encodes any value (prevents markup/script injection from AD or Entra object names).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(ValueFromPipeline)] [AllowNull()] [object] $Value
    )

    process {
        if ($null -eq $Value) { return '' }
        [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }
}

function ConvertTo-IGLinkedHtml {
    <#
    .SYNOPSIS
        Encodes text, then turns https:// URLs (already encoded, so quote-free) into links.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [object] $Value
    )

    $encoded = ConvertTo-IGHtml -Value $Value
    $encoded -replace '(https://[^\s<>"'']+)', '<a href="$1" rel="noopener noreferrer">$1</a>'
}

function Get-IGSeverityClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Severity
    )

    if ($Severity -and $script:IGSeverityCssClass.ContainsKey($Severity)) {
        return $script:IGSeverityCssClass[$Severity]
    }
    'sev-info'
}

function Get-IGStatusClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Status
    )

    switch ($Status) {
        { $_ -eq $script:IGStatus.Pass } { return 'st-pass' }
        { $_ -eq $script:IGStatus.Fail } { return 'st-fail' }
        default { return 'st-notrun' }
    }
}

function Get-IGFindingAnchor {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Id
    )

    'f-' + (($Id.ToLowerInvariant()) -replace '[^a-z0-9-]', '')
}

function Get-IGFindingSortKey {
    <#
    .SYNOPSIS
        Sort rank: failing findings first, then by severity, then not-run, then compliant.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $statusRank = switch ($Finding.Status) {
        { $_ -eq $script:IGStatus.Fail } { 0; break }
        { $_ -eq $script:IGStatus.NotRun } { 1; break }
        default { 2 }
    }
    $severityRank = [array]::IndexOf($script:IGSeverityOrder, [string]$Finding.Severity)
    ($statusRank * 10) + [math]::Max($severityRank, 0)
}
