function Test-IGAdPasswordNotRequired {
    <#
    .SYNOPSIS
        AD-009: enabled accounts flagged PASSWD_NOTREQD (an empty password may be set).
    #>
    [CmdletBinding()]
    param()

    $accounts = @(Get-IGEnabledAdUser | Where-Object { $_.PasswordNotRequired -eq $true })

    $items = foreach ($account in $accounts) {
        New-IGItem -Name (Get-IGAdAccountName -Account $account) -Detail (Get-IGPrivilegeLabel -Account $account)
    }

    $severity = Get-IGAccountSeverity -Accounts $accounts -DefaultSeverity 'Élevée'
    New-IGFinding -Id 'AD-009' -Severity $severity -Items $items
}
