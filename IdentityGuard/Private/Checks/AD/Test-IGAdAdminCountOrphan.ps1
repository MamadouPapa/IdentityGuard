function Test-IGAdAdminCountOrphan {
    <#
    .SYNOPSIS
        AD-008: accounts with adminCount=1 that are no longer members of any protected group.
    #>
    [CmdletBinding()]
    param()

    $protectedNames = @(Get-IGSource -Name 'ADPrivilegedMembers' | ForEach-Object { $_.SamAccountName } | Sort-Object -Unique)

    $orphans = @(Get-IGSource -Name 'ADUsers' | Where-Object {
            (Test-IGAdIsProtected -Account $_) -and
            -not (Test-IGAdIsKrbtgt -Account $_) -and
            $protectedNames -notcontains [string]$_.SamAccountName
        })

    $items = foreach ($account in $orphans) {
        $state = if ($account.Enabled -eq $true) { 'Actif' } else { 'Désactivé' }
        New-IGItem -Name (Get-IGAdAccountName -Account $account) -Detail ('{0} · adminCount=1 sans appartenance à un groupe protégé' -f $state)
    }

    New-IGFinding -Id 'AD-008' -Severity 'Faible' -Items $items
}
