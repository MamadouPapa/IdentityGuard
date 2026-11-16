function Test-IGAdInactiveAccount {
    <#
    .SYNOPSIS
        AD-003: enabled user accounts without logon (lastLogonTimestamp) for more than the threshold.
    #>
    [CmdletBinding()]
    param()

    $days = $script:IGThresholds.InactiveDays
    $accounts = @(Get-IGEnabledAdUser | Where-Object {
            Test-IGIsStale -LastActivity $_.lastLogonTimestamp -Created $_.whenCreated -Days $days
        })

    $items = foreach ($account in $accounts) {
        New-IGItem -Name (Get-IGAdAccountName -Account $account) `
            -Detail (Get-IGActivityDetail -LastActivity $account.lastLogonTimestamp -Created $account.whenCreated)
    }

    New-IGFinding -Id 'AD-003' -Severity 'Moyenne' -Items $items -Note ("Seuil : {0} jours d'inactivité." -f $days)
}
