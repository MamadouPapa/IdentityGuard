function Test-IGAdAsRepRoastable {
    <#
    .SYNOPSIS
        AD-005: enabled accounts with DoesNotRequirePreAuth (AS-REP roasting, T1558.004).
    #>
    [CmdletBinding()]
    param()

    $accounts = @(Get-IGEnabledAdUser | Where-Object { $_.DoesNotRequirePreAuth -eq $true })

    $items = foreach ($account in $accounts) {
        New-IGItem -Name (Get-IGAdAccountName -Account $account) -Detail (Get-IGPrivilegeLabel -Account $account)
    }

    $severity = Get-IGAccountSeverity -Accounts $accounts -DefaultSeverity 'Élevée'
    New-IGFinding -Id 'AD-005' -Severity $severity -Items $items
}
