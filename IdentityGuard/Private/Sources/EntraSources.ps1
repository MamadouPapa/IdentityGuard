# Live Entra ID collectors. Read-only: only Get-Mg* cmdlets of the Microsoft.Graph SDK.

$script:IGGraphUserProperties = @(
    'id', 'displayName', 'userPrincipalName', 'accountEnabled', 'userType', 'createdDateTime', 'externalUserState'
)

function Assert-IGGraphConnection {
    Assert-IGCommand -Name 'Get-MgContext' -Module 'Microsoft.Graph.Authentication'
    if ($null -eq (Get-MgContext)) {
        throw 'non connecté à Microsoft Graph : exécutez Connect-MgGraph avec les scopes en lecture seule (voir README).'
    }
}

function Get-IGEntraOrganizationData {
    Assert-IGGraphConnection
    Assert-IGCommand -Name 'Get-MgOrganization' -Module 'Microsoft.Graph.Identity.DirectoryManagement'
    Get-MgOrganization -ErrorAction Stop
}

function Get-IGEntraRegistrationData {
    Assert-IGGraphConnection
    Assert-IGCommand -Name 'Get-MgReportAuthenticationMethodUserRegistrationDetail' -Module 'Microsoft.Graph.Reports'
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
}

function Get-IGEntraUserData {
    Assert-IGGraphConnection
    Assert-IGCommand -Name 'Get-MgUser' -Module 'Microsoft.Graph.Users'
    Get-MgUser -All -Property $script:IGGraphUserProperties -ErrorAction Stop
}

function Get-IGEntraUserSignInData {
    <#
    .SYNOPSIS
        Users including signInActivity. Requires Entra ID P1 and AuditLog.Read.All.
    #>
    Assert-IGGraphConnection
    Assert-IGCommand -Name 'Get-MgUser' -Module 'Microsoft.Graph.Users'
    try {
        Get-MgUser -All -Property ($script:IGGraphUserProperties + 'signInActivity') -ErrorAction Stop
    }
    catch {
        throw ("signInActivity indisponible (licence Entra ID P1 et permission AuditLog.Read.All requises) : {0}" -f $_.Exception.Message)
    }
}

function ConvertTo-IGRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Assignment,
        [Parameter(Mandatory)] [string] $Source
    )

    [pscustomobject]@{
        PrincipalId      = [string]$Assignment.PrincipalId
        RoleDefinitionId = [string]$Assignment.RoleDefinitionId
        AssignmentType   = [string]$Assignment.AssignmentType
        EndDateTime      = $Assignment.EndDateTime
        Source           = $Source
    }
}

function Get-IGEntraRoleAssignmentData {
    <#
    .SYNOPSIS
        Active role assignments. Uses PIM schedule instances when available, otherwise direct assignments
        (without PIM every active assignment is permanent).
    #>
    Assert-IGGraphConnection

    try {
        Assert-IGCommand -Name 'Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance' -Module 'Microsoft.Graph.Identity.Governance'
        # Collected fully before conversion so a mid-stream failure cannot produce duplicates.
        $instances = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop)
        return $instances | ForEach-Object { ConvertTo-IGRoleAssignment -Assignment $_ -Source 'PIM' }
    }
    catch {
        Write-Verbose "PIM schedule instances unavailable, falling back to direct assignments: $($_.Exception.Message)"
    }

    Assert-IGCommand -Name 'Get-MgRoleManagementDirectoryRoleAssignment' -Module 'Microsoft.Graph.Identity.Governance'
    Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop |
        ForEach-Object { ConvertTo-IGRoleAssignment -Assignment $_ -Source 'Direct' }
}

function Get-IGEntraSecurityDefaultsData {
    Assert-IGGraphConnection
    Assert-IGCommand -Name 'Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy' -Module 'Microsoft.Graph.Identity.SignIns'
    Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
}

function Get-IGEntraConditionalAccessData {
    Assert-IGGraphConnection
    Assert-IGCommand -Name 'Get-MgIdentityConditionalAccessPolicy' -Module 'Microsoft.Graph.Identity.SignIns'
    Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
}

function Get-IGEntraApplicationData {
    Assert-IGGraphConnection
    Assert-IGCommand -Name 'Get-MgApplication' -Module 'Microsoft.Graph.Applications'
    Get-MgApplication -All -Property 'id', 'appId', 'displayName', 'passwordCredentials', 'keyCredentials' -ErrorAction Stop
}
