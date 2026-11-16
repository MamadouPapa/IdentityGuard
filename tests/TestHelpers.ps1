# Shared test helpers: imports the module, defines stubs for AD/Graph cmdlets (so Pester can mock
# them on machines without RSAT or the Graph SDK) and small factories for fake directory objects.

$IGTestModulePath = Join-Path $PSScriptRoot '../IdentityGuard/IdentityGuard.psd1'

# --- Cmdlet stubs (never called for real: every test mocks what it uses) ---------------------------
function global:Get-ADUser { [CmdletBinding()] param($Filter, $Properties, $Identity, $Server) }
function global:Get-ADComputer { [CmdletBinding()] param($Filter, $Properties, $Server) }
function global:Get-ADDomain { [CmdletBinding()] param($Identity, $Server) }
function global:Get-ADForest { [CmdletBinding()] param($Identity, $Server) }
function global:Get-ADGroupMember { [CmdletBinding()] param($Identity, $Server, [switch] $Recursive) }
function global:Get-ADRootDSE { [CmdletBinding()] param($Server) }
function global:Get-ADObject { [CmdletBinding()] param($SearchBase, $LDAPFilter, $Properties, $Server) }
function global:Get-MgContext { [CmdletBinding()] param() }
function global:Get-MgOrganization { [CmdletBinding()] param() }
function global:Get-MgReportAuthenticationMethodUserRegistrationDetail { [CmdletBinding()] param([switch] $All) }
function global:Get-MgUser { [CmdletBinding()] param([switch] $All, $Property) }
function global:Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance { [CmdletBinding()] param([switch] $All) }
function global:Get-MgRoleManagementDirectoryRoleAssignment { [CmdletBinding()] param([switch] $All) }
function global:Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy { [CmdletBinding()] param() }
function global:Get-MgIdentityConditionalAccessPolicy { [CmdletBinding()] param([switch] $All) }
function global:Get-MgApplication { [CmdletBinding()] param([switch] $All, $Property) }

# --- Factories ------------------------------------------------------------------------------------
function global:New-IGTestAdUser {
    param([string] $Sam, [hashtable] $Property = @{})

    $user = [ordered]@{
        SamAccountName        = $Sam
        UserPrincipalName     = "$Sam@corp.contoso.example"
        Enabled               = $true
        PasswordNeverExpires  = $false
        PasswordNotRequired   = $false
        DoesNotRequirePreAuth = $false
        ServicePrincipalName  = @()
        AdminCount            = $null
        lastLogonTimestamp    = (Get-Date).AddDays(-1).ToFileTime()
        PasswordLastSet       = (Get-Date).AddDays(-10)
        whenCreated           = (Get-Date).AddDays(-400)
        DistinguishedName     = "CN=$Sam,OU=Users,DC=corp,DC=contoso,DC=example"
    }
    foreach ($key in $Property.Keys) { $user[$key] = $Property[$key] }
    [pscustomobject]$user
}

function global:New-IGTestComputer {
    param([string] $Name, [int] $PrimaryGroupId = 515, [bool] $Trusted = $false, [bool] $Enabled = $true)

    [pscustomobject]@{
        Name                 = $Name
        Enabled              = $Enabled
        TrustedForDelegation = $Trusted
        PrimaryGroupID       = $PrimaryGroupId
        OperatingSystem      = 'Windows Server 2022 Standard'
        DistinguishedName    = "CN=$Name,OU=Servers,DC=corp,DC=contoso,DC=example"
    }
}

function global:New-IGTestMember {
    param([string] $Sam)
    [pscustomobject]@{ SamAccountName = $Sam; objectClass = 'user'; distinguishedName = "CN=$Sam,DC=corp,DC=contoso,DC=example" }
}

function global:New-IGTestEntraUser {
    param([string] $Id, [string] $Upn, [string] $UserType = 'Member', [hashtable] $Property = @{})

    $user = [ordered]@{
        Id                = $Id
        UserPrincipalName = $Upn
        DisplayName       = $Upn
        AccountEnabled    = $true
        UserType          = $UserType
        CreatedDateTime   = (Get-Date).AddDays(-400)
        ExternalUserState = $null
        SignInActivity    = $null
    }
    foreach ($key in $Property.Keys) { $user[$key] = $Property[$key] }
    [pscustomobject]$user
}

function global:New-IGTestSignIn {
    param([Nullable[int]] $DaysAgo)
    if ($null -eq $DaysAgo) { return [pscustomobject]@{ LastSignInDateTime = $null; LastNonInteractiveSignInDateTime = $null } }
    [pscustomobject]@{ LastSignInDateTime = (Get-Date).AddDays(-$DaysAgo); LastNonInteractiveSignInDateTime = $null }
}

# --- Check runners --------------------------------------------------------------------------------
function global:Invoke-IGTestCheck {
    <#
    .SYNOPSIS
        Runs one check function directly (exceptions surface) with a fresh source cache.
    #>
    param([Parameter(Mandatory)] [string] $Id)

    InModuleScope IdentityGuard -Parameters @{ CheckId = $Id } {
        param($CheckId)
        $script:IGSourceCache = @{}
        $script:IGDemoMode = $false
        & (Get-IGCheckDefinition -Id $CheckId).Function
    }
}

function global:Invoke-IGTestCheckSafe {
    <#
    .SYNOPSIS
        Runs one check through Invoke-IGCheck (error isolation) with a fresh source cache.
    #>
    param([Parameter(Mandatory)] [string] $Id)

    InModuleScope IdentityGuard -Parameters @{ CheckId = $Id } {
        param($CheckId)
        $script:IGSourceCache = @{}
        $script:IGDemoMode = $false
        Invoke-IGCheck -Definition (Get-IGCheckDefinition -Id $CheckId)
    }
}
