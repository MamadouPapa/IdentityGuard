# Small helpers shared by the Entra ID checks.

function Get-IGLastSignIn {
    <#
    .SYNOPSIS
        Most recent interactive or non-interactive sign-in from signInActivity, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $User
    )

    $activity = $User.SignInActivity
    if ($null -eq $activity) { return $null }

    $dates = @(
        (ConvertTo-IGDateTime -Value $activity.LastSignInDateTime)
        (ConvertTo-IGDateTime -Value $activity.LastNonInteractiveSignInDateTime)
    ) | Where-Object { $null -ne $_ }

    $dates | Sort-Object -Descending | Select-Object -First 1
}

function Test-IGEntraIsGuest {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [object] $User
    )

    [string]$User.UserType -eq 'Guest'
}

function Get-IGEntraUserName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object] $User
    )

    if ($User.UserPrincipalName) { return [string]$User.UserPrincipalName }
    if ($User.DisplayName) { return [string]$User.DisplayName }
    [string]$User.Id
}

function Get-IGStaleSignInUser {
    <#
    .SYNOPSIS
        Filters enabled users whose last sign-in (or creation, if never signed in) is older than $Days.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] [object[]] $Users = @(),
        [Parameter(Mandatory)] [int] $Days
    )

    $Users | Where-Object {
        $null -ne $_ -and $_.AccountEnabled -eq $true -and
        (Test-IGIsStale -LastActivity (Get-IGLastSignIn -User $_) -Created $_.CreatedDateTime -Days $Days)
    }
}

function New-IGSignInItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $User
    )

    $detail = Get-IGActivityDetail -LastActivity (Get-IGLastSignIn -User $User) -Created $User.CreatedDateTime
    New-IGItem -Name (Get-IGEntraUserName -User $User) -Detail $detail
}
