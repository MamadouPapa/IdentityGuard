# Small helpers shared by the Active Directory checks.

function Get-IGEnabledAdUser {
    [CmdletBinding()]
    param()

    Get-IGSource -Name 'ADUsers' | Where-Object { $_.Enabled -eq $true }
}

function Get-IGNonDcComputer {
    <#
    .SYNOPSIS
        Enabled computers that are not (RO)DCs, based on primaryGroupID.
    #>
    [CmdletBinding()]
    param()

    Get-IGSource -Name 'ADComputers' | Where-Object {
        $_.Enabled -eq $true -and $script:IGDomainControllerGroupIds -notcontains [int]$_.PrimaryGroupID
    }
}

function Get-IGAdAccountName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object] $Account
    )

    if ($Account.SamAccountName) { return [string]$Account.SamAccountName }
    if ($Account.UserPrincipalName) { return [string]$Account.UserPrincipalName }
    [string]$Account.DistinguishedName
}

function Test-IGAdIsProtected {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [object] $Account
    )

    [int]$Account.AdminCount -eq 1
}

function Test-IGAdIsKrbtgt {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [object] $Account
    )

    $name = [string]$Account.SamAccountName
    $name -eq 'krbtgt' -or $name -like 'krbtgt_*'
}

function Get-IGPrivilegeLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object] $Account
    )

    if (Test-IGAdIsProtected -Account $Account) { return 'Compte à privilèges (adminCount=1)' }
    'Compte standard'
}

function Get-IGAccountSeverity {
    <#
    .SYNOPSIS
        Escalates to 'Critique' when at least one affected account is privileged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()] [object[]] $Accounts = @(),
        [Parameter(Mandatory)] [string] $DefaultSeverity
    )

    $privileged = @($Accounts | Where-Object { $null -ne $_ -and (Test-IGAdIsProtected -Account $_) })
    if ($privileged.Count -gt 0) { return 'Critique' }
    $DefaultSeverity
}
