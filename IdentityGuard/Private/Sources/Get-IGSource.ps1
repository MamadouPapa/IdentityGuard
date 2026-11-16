# Data access layer. Checks never call AD/Graph cmdlets directly: they ask for a named source,
# which is collected once per run (live or demo fixture) and cached, including failures.

$script:IGLiveSourceMap = @{
    ADDomain              = 'Get-IGAdDomainData'
    ADUsers               = 'Get-IGAdUserData'
    ADComputers           = 'Get-IGAdComputerData'
    ADPrivilegedMembers   = 'Get-IGAdPrivilegedMemberData'
    ADLapsSchema          = 'Get-IGAdLapsSchemaData'
    EntraOrganization     = 'Get-IGEntraOrganizationData'
    EntraRegistration     = 'Get-IGEntraRegistrationData'
    EntraUsers            = 'Get-IGEntraUserData'
    EntraUsersSignIn      = 'Get-IGEntraUserSignInData'
    EntraRoleAssignments  = 'Get-IGEntraRoleAssignmentData'
    EntraSecurityDefaults = 'Get-IGEntraSecurityDefaultsData'
    EntraCAPolicies       = 'Get-IGEntraConditionalAccessData'
    EntraApplications     = 'Get-IGEntraApplicationData'
}

function Get-IGSource {
    <#
    .SYNOPSIS
        Returns the (cached) records of a named data source; throws the cached error if collection failed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    if (-not $script:IGSourceCache.ContainsKey($Name)) {
        $script:IGSourceCache[$Name] = Read-IGSource -Name $Name
    }

    $entry = $script:IGSourceCache[$Name]
    if ($entry.Error) {
        throw $entry.Error
    }
    $entry.Data
}

function Get-IGOptionalSource {
    <#
    .SYNOPSIS
        Like Get-IGSource but returns $null (instead of throwing) when the source is unavailable.
        Returns the records as a single array so an empty result can be told apart from $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    try {
        $records = @(Get-IGSource -Name $Name)
        return , $records
    }
    catch {
        Write-Verbose ("Optional source '{0}' unavailable: {1}" -f $Name, $_.Exception.Message)
        return $null
    }
}

function Read-IGSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    try {
        $raw = if ($script:IGDemoMode) {
            Get-IGDemoSource -Name $Name
        }
        else {
            Get-IGLiveSource -Name $Name
        }
        @{ Data = @($raw | Where-Object { $null -ne $_ }); Error = $null }
    }
    catch {
        @{ Data = @(); Error = $_.Exception.Message }
    }
}

function Get-IGLiveSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    if (-not $script:IGLiveSourceMap.ContainsKey($Name)) {
        throw "Unknown data source '$Name'."
    }
    & $script:IGLiveSourceMap[$Name]
}

function Assert-IGCommand {
    <#
    .SYNOPSIS
        Throws a readable error when a required cmdlet (and thus its module) is not available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Module
    )

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw ("commande {0} introuvable : installez ou importez le module {1}." -f $Name, $Module)
    }
}
