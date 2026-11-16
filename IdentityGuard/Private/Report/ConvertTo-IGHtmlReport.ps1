function ConvertTo-IGHtmlReport {
    <#
    .SYNOPSIS
        Renders findings as a single self-contained HTML document (inline CSS, no script, no external assets).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Finding,
        [Parameter(Mandatory)] [pscustomobject] $Context
    )

    $sorted = @($Finding | Where-Object { $null -ne $_ } |
            Sort-Object -Property @{ Expression = { Get-IGFindingSortKey -Finding $_ } }, Id)

    $details = foreach ($f in $sorted) { New-IGHtmlFindingDetail -Finding $f }

    @(
        '<!DOCTYPE html>'
        '<html lang="fr">'
        '<head>'
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        ('<title>IdentityGuard – {0}</title>' -f (ConvertTo-IGHtml $Context.Target))
        '<style>'
        $script:IGReportCss
        '</style>'
        '</head>'
        '<body>'
        '<main class="page">'
        (New-IGHtmlHeader -Context $Context)
        (New-IGHtmlSummary -Finding $sorted)
        (New-IGHtmlFindingTable -Finding $sorted)
        '<h2>Détail des contrôles</h2>'
        (@($details) -join "`n")
        (New-IGHtmlFooter -Context $Context)
        '</main>'
        '</body>'
        '</html>'
    ) -join "`n"
}
