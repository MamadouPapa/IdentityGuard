function New-IGItem {
    <#
    .SYNOPSIS
        Creates one affected-object entry (name + human-readable detail).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Name,
        [AllowNull()] [string] $Detail = ''
    )

    [pscustomobject]@{
        Name   = $Name
        Detail = $Detail
    }
}

function New-IGFindingObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Definition,
        [Parameter(Mandatory)] [string] $Severity,
        [Parameter(Mandatory)] [string] $Status,
        [int] $Count = 0,
        [AllowEmptyCollection()] [object[]] $Items = @(),
        [string] $Note = ''
    )

    [pscustomobject]@{
        PSTypeName  = 'IdentityGuard.Finding'
        Id          = $Definition.Id
        Category    = $Definition.Category
        Title       = $Definition.Title
        Severity    = $Severity
        Status      = $Status
        Count       = $Count
        Items       = $Items
        Note        = $Note
        Remediation = $Definition.Remediation
        Reference   = $Definition.Reference
    }
}

function New-IGFinding {
    <#
    .SYNOPSIS
        Builds the uniform finding object returned by every check.
    .DESCRIPTION
        Metadata comes from the check catalog. By default a finding is compliant when Count is 0;
        compliant findings are always reported with Severity 'Info'.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,

        [Parameter(Mandatory)]
        [ValidateSet('Critique', 'Élevée', 'Moyenne', 'Faible', 'Info')]
        [string] $Severity,

        [AllowNull()] [AllowEmptyCollection()] [object[]] $Items = @(),

        # -1 means "use the number of items".
        [int] $Count = -1,

        [Nullable[bool]] $IsCompliant = $null,

        [string] $Note = ''
    )

    $definition = Get-IGCheckDefinition -Id $Id
    $safeItems = @($Items | Where-Object { $null -ne $_ })
    $finalCount = if ($Count -ge 0) { $Count } else { $safeItems.Count }
    $compliant = if ($null -ne $IsCompliant) { [bool]$IsCompliant } else { $finalCount -eq 0 }

    $status = if ($compliant) { $script:IGStatus.Pass } else { $script:IGStatus.Fail }
    $effectiveSeverity = if ($compliant) { 'Info' } else { $Severity }

    New-IGFindingObject -Definition $definition -Severity $effectiveSeverity -Status $status `
        -Count $finalCount -Items $safeItems -Note $Note
}

function New-IGNotRunFinding {
    <#
    .SYNOPSIS
        Builds the Info finding emitted when a check cannot run (module, permission, licence...).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Reason
    )

    $definition = Get-IGCheckDefinition -Id $Id
    New-IGFindingObject -Definition $definition -Severity 'Info' -Status $script:IGStatus.NotRun `
        -Count 0 -Items @() -Note ("Contrôle non exécuté : {0}" -f $Reason)
}
