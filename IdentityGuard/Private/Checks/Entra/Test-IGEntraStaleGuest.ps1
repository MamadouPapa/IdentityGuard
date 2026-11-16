function Get-IGPendingGuest {
    <#
    .SYNOPSIS
        Fallback without signInActivity: invitations still pending after the threshold.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] [object[]] $Guests = @()
    )

    $days = $script:IGThresholds.GuestPendingDays
    $Guests | Where-Object {
        $null -ne $_ -and [string]$_.ExternalUserState -eq 'PendingAcceptance' -and
        (Test-IGIsStale -LastActivity $null -Created $_.CreatedDateTime -Days $days)
    }
}

function Test-IGEntraStaleGuest {
    <#
    .SYNOPSIS
        ENT-003: guest accounts without recent sign-in, or with long-pending invitations when
        signInActivity (Entra ID P1) is not available.
    #>
    [CmdletBinding()]
    param()

    $signInUsers = Get-IGOptionalSource -Name 'EntraUsersSignIn'

    if ($null -ne $signInUsers) {
        $guests = @($signInUsers | Where-Object { Test-IGEntraIsGuest -User $_ })
        $stale = @(Get-IGStaleSignInUser -Users $guests -Days $script:IGThresholds.GuestStaleDays)
        $items = foreach ($guest in $stale) { New-IGSignInItem -User $guest }
        $method = 'sans connexion depuis {0} jours (signInActivity)' -f $script:IGThresholds.GuestStaleDays
    }
    else {
        $guests = @(Get-IGSource -Name 'EntraUsers' | Where-Object { Test-IGEntraIsGuest -User $_ })
        $stale = @(Get-IGPendingGuest -Guests $guests)
        $items = foreach ($guest in $stale) {
            New-IGItem -Name (Get-IGEntraUserName -User $guest) -Detail ('Invitation non acceptée depuis le {0}' -f (Format-IGDate $guest.CreatedDateTime))
        }
        $method = 'invitation en attente depuis plus de {0} jours (signInActivity indisponible, licence P1 requise pour la date de connexion)' -f $script:IGThresholds.GuestPendingDays
    }

    $note = '{0} invité(s) au total ; critère : {1}.' -f $guests.Count, $method
    New-IGFinding -Id 'ENT-003' -Severity 'Moyenne' -Items $items -Note $note
}
