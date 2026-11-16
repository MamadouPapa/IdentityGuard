# Builders for each section of the HTML report. All dynamic values are HTML-encoded.

function New-IGHtmlHeader {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Context
    )

    $meta = 'Cible : {0} · Périmètre : {1} · Généré le : {2}' -f `
    (ConvertTo-IGHtml $Context.Target), (ConvertTo-IGHtml $Context.Scope), (ConvertTo-IGHtml $Context.GeneratedAt)
    $badge = if ($Context.IsDemo) { '<div class="demo-badge">MODE DÉMO · DONNÉES FICTIVES</div>' } else { '' }

    @(
        '<header class="report-header">'
        '<div>'
        '<p class="eyebrow">IdentityGuard · Audit en lecture seule</p>'
        '<h1>Rapport de posture de sécurité des identités</h1>'
        ('<p class="meta">{0}</p>' -f $meta)
        '</div>'
        $badge
        '</header>'
    ) -join "`n"
}

function New-IGHtmlCounter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $CssClass,
        [Parameter(Mandatory)] [int] $Value,
        [Parameter(Mandatory)] [string] $Label
    )

    '<div class="card counter {0}"><div class="value">{1}</div><div class="label">{2}</div></div>' -f `
        $CssClass, $Value, (ConvertTo-IGHtml $Label)
}

function New-IGHtmlSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()] [object[]] $Finding = @()
    )

    $score = Get-IGSecurityScore -Finding $Finding
    $failing = @($Finding | Where-Object { $_.Status -eq $script:IGStatus.Fail })

    $counters = foreach ($severity in ($script:IGSeverityOrder | Where-Object { $_ -ne 'Info' })) {
        $count = @($failing | Where-Object { $_.Severity -eq $severity }).Count
        New-IGHtmlCounter -CssClass (Get-IGSeverityClass $severity) -Value $count -Label $severity
    }
    $counters = @($counters) + @(
        (New-IGHtmlCounter -CssClass 'st-pass' -Value $score.Passed -Label 'Conformes')
        (New-IGHtmlCounter -CssClass 'sev-info' -Value $score.NotRun -Label 'Non exécutés')
    )

    @(
        '<section class="summary">'
        '<div class="card score">'
        '<div class="score-label">Score de posture</div>'
        ('<div class="score-value">{0}<span class="score-label">/100</span></div>' -f $score.Score)
        ('<div class="score-grade">Niveau {0}</div>' -f (ConvertTo-IGHtml $score.Grade))
        ('<div class="score-label" style="margin-top:8px">{0} contrôle(s) à corriger sur {1}</div>' -f $score.Failed, $Finding.Count)
        '</div>'
        ('<div class="counters">{0}</div>' -f ($counters -join ''))
        '</section>'
    ) -join "`n"
}

function New-IGHtmlFindingTable {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()] [object[]] $Finding = @()
    )

    $rows = foreach ($f in $Finding) {
        '<tr><td><a href="#{0}">{1}</a></td><td>{2}</td><td>{3}</td><td><span class="badge {4}">{5}</span></td><td><span class="status {6}">{7}</span></td><td class="num">{8}</td></tr>' -f `
        (Get-IGFindingAnchor $f.Id), (ConvertTo-IGHtml $f.Id), (ConvertTo-IGHtml $f.Category), (ConvertTo-IGHtml $f.Title),
        (Get-IGSeverityClass $f.Severity), (ConvertTo-IGHtml $f.Severity),
        (Get-IGStatusClass $f.Status), (ConvertTo-IGHtml $f.Status), [int]$f.Count
    }

    @(
        '<h2>Synthèse des contrôles</h2>'
        '<div class="table-wrap"><table>'
        '<thead><tr><th>Id</th><th>Catégorie</th><th>Contrôle</th><th>Sévérité</th><th>Statut</th><th class="num">Nombre</th></tr></thead>'
        ('<tbody>{0}</tbody>' -f (@($rows) -join "`n"))
        '</table></div>'
    ) -join "`n"
}

function New-IGHtmlItemTable {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()] [object[]] $Items = @()
    )

    $safeItems = @($Items | Where-Object { $null -ne $_ })
    if ($safeItems.Count -eq 0) {
        return '<p class="empty">Aucun objet concerné.</p>'
    }

    $max = $script:IGReportMaxItems
    $rows = foreach ($item in ($safeItems | Select-Object -First $max)) {
        '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-IGHtml $item.Name), (ConvertTo-IGHtml $item.Detail)
    }

    $truncated = ''
    if ($safeItems.Count -gt $max) {
        $truncated = '<p class="truncated">… et {0} autre(s) objet(s) non affiché(s). Utilisez l''objet retourné par Invoke-IdentityGuard pour la liste complète.</p>' -f ($safeItems.Count - $max)
    }

    '<table class="items"><thead><tr><th>Objet</th><th>Détail</th></tr></thead><tbody>{0}</tbody></table>{1}' -f `
    (@($rows) -join "`n"), $truncated
}

function New-IGHtmlFindingDetail {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $isFailing = $Finding.Status -eq $script:IGStatus.Fail
    $open = if ($isFailing -and @('Critique', 'Élevée') -contains $Finding.Severity) { ' open' } else { '' }
    $classes = '{0} {1}' -f (Get-IGSeverityClass $Finding.Severity), (Get-IGStatusClass $Finding.Status)
    $note = if ($Finding.Note) { '<p class="note">{0}</p>' -f (ConvertTo-IGHtml $Finding.Note) } else { '' }

    @(
        ('<details id="{0}" class="finding {1}"{2}>' -f (Get-IGFindingAnchor $Finding.Id), $classes, $open)
        ('<summary><span class="badge {0}">{1}</span><span class="fid">{2}</span><span class="ftitle">{3}</span><span class="fcount">{4} · {5} objet(s)</span></summary>' -f `
            (Get-IGSeverityClass $Finding.Severity), (ConvertTo-IGHtml $Finding.Severity), (ConvertTo-IGHtml $Finding.Id),
            (ConvertTo-IGHtml $Finding.Title), (ConvertTo-IGHtml $Finding.Status), [int]$Finding.Count)
        '<div class="finding-body">'
        $note
        ('<h3>Remédiation</h3><p>{0}</p>' -f (ConvertTo-IGHtml $Finding.Remediation))
        ('<h3>Références</h3><p>{0}</p>' -f (ConvertTo-IGLinkedHtml $Finding.Reference))
        ('<h3>Objets concernés</h3>{0}' -f (New-IGHtmlItemTable -Items @($Finding.Items)))
        '</div>'
        '</details>'
    ) -join "`n"
}

function New-IGHtmlFooter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Context
    )

    $demo = if ($Context.IsDemo) { ' Les données de ce rapport sont entièrement fictives.' } else { ' Ce rapport contient des informations sensibles : diffusion restreinte.' }
    '<footer>Généré par IdentityGuard v{0} — collecte en lecture seule (cmdlets Get-* uniquement), aucune modification de l''annuaire.{1}</footer>' -f `
    (ConvertTo-IGHtml $Context.Version), (ConvertTo-IGHtml $demo)
}
