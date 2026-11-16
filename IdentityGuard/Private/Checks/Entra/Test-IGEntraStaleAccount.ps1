function Test-IGEntraStaleAccount {
    <#
    .SYNOPSIS
        ENT-006: enabled member accounts without sign-in for more than the threshold.
        Requires signInActivity (Entra ID P1); otherwise the check is reported as not executed.
    #>
    [CmdletBinding()]
    param()

    $days = $script:IGThresholds.InactiveDays
    $members = @(Get-IGSource -Name 'EntraUsersSignIn' | Where-Object { -not (Test-IGEntraIsGuest -User $_) })
    $stale = @(Get-IGStaleSignInUser -Users $members -Days $days)

    $items = foreach ($user in $stale) { New-IGSignInItem -User $user }

    New-IGFinding -Id 'ENT-006' -Severity 'Moyenne' -Items $items -Note ("Seuil : {0} jours sans connexion." -f $days)
}
