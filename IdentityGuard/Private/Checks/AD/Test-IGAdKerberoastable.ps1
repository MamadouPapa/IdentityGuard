function Test-IGAdKerberoastable {
    <#
    .SYNOPSIS
        AD-006: enabled user accounts (krbtgt excluded) carrying an SPN (Kerberoasting, T1558.003).
    #>
    [CmdletBinding()]
    param()

    $accounts = @(Get-IGEnabledAdUser | Where-Object {
            -not (Test-IGAdIsKrbtgt -Account $_) -and @($_.ServicePrincipalName | Where-Object { $_ }).Count -gt 0
        })

    $items = foreach ($account in $accounts) {
        $spns = @($account.ServicePrincipalName | Where-Object { $_ })
        $detail = 'SPN : {0} · {1}' -f ($spns -join ', '), (Get-IGPrivilegeLabel -Account $account)
        New-IGItem -Name (Get-IGAdAccountName -Account $account) -Detail $detail
    }

    $severity = Get-IGAccountSeverity -Accounts $accounts -DefaultSeverity 'Élevée'
    New-IGFinding -Id 'AD-006' -Severity $severity -Items $items
}
