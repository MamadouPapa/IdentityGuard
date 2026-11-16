function Test-IGAdPasswordNeverExpires {
    <#
    .SYNOPSIS
        AD-002: enabled accounts with PasswordNeverExpires.
    #>
    [CmdletBinding()]
    param()

    $accounts = @(Get-IGEnabledAdUser | Where-Object { $_.PasswordNeverExpires -eq $true })

    $items = foreach ($account in $accounts) {
        $detail = 'Mot de passe défini le {0} · {1}' -f (Format-IGDate $account.PasswordLastSet), (Get-IGPrivilegeLabel -Account $account)
        New-IGItem -Name (Get-IGAdAccountName -Account $account) -Detail $detail
    }

    New-IGFinding -Id 'AD-002' -Severity 'Moyenne' -Items $items
}
