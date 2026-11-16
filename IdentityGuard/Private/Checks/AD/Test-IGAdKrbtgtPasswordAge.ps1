function Test-IGAdKrbtgtPasswordAge {
    <#
    .SYNOPSIS
        AD-001: krbtgt (and RODC krbtgt_*) password older than the threshold (Golden Ticket persistence).
    #>
    [CmdletBinding()]
    param()

    $maxAge = $script:IGThresholds.KrbtgtMaxAgeDays
    $accounts = @(Get-IGSource -Name 'ADUsers' | Where-Object { Test-IGAdIsKrbtgt -Account $_ })
    if ($accounts.Count -eq 0) {
        throw 'compte krbtgt introuvable dans les données Active Directory.'
    }

    $items = foreach ($account in $accounts) {
        $lastSet = ConvertTo-IGDateTime -Value $account.PasswordLastSet
        if ($null -eq $lastSet) {
            New-IGItem -Name $account.SamAccountName -Detail 'Date du dernier changement inconnue'
            continue
        }

        $age = Get-IGDaysSince -Date $lastSet
        if ($age -gt $maxAge) {
            $detail = 'Mot de passe changé le {0} (il y a {1} jours)' -f (Format-IGDate $lastSet), $age
            New-IGItem -Name $account.SamAccountName -Detail $detail
        }
    }

    New-IGFinding -Id 'AD-001' -Severity 'Élevée' -Items $items -Note ("Seuil : {0} jours." -f $maxAge)
}
