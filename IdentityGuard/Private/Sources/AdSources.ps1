# Live Active Directory collectors. Read-only: only Get-* cmdlets of the ActiveDirectory module.

$script:IGAdUserProperties = @(
    'SamAccountName', 'UserPrincipalName', 'Enabled', 'PasswordNeverExpires', 'PasswordNotRequired',
    'DoesNotRequirePreAuth', 'ServicePrincipalName', 'AdminCount', 'lastLogonTimestamp',
    'PasswordLastSet', 'whenCreated', 'DistinguishedName'
)

$script:IGAdComputerProperties = @(
    'Name', 'Enabled', 'TrustedForDelegation', 'PrimaryGroupID', 'OperatingSystem', 'DistinguishedName'
)

$script:IGLapsSchemaFilter = '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))'

function Get-IGAdDomainData {
    Assert-IGCommand -Name 'Get-ADDomain' -Module 'ActiveDirectory (RSAT)'
    Get-ADDomain -ErrorAction Stop
}

function Get-IGAdUserData {
    Assert-IGCommand -Name 'Get-ADUser' -Module 'ActiveDirectory (RSAT)'
    Get-ADUser -Filter * -Properties $script:IGAdUserProperties -ErrorAction Stop
}

function Get-IGAdComputerData {
    Assert-IGCommand -Name 'Get-ADComputer' -Module 'ActiveDirectory (RSAT)'
    Get-ADComputer -Filter * -Properties $script:IGAdComputerProperties -ErrorAction Stop
}

function Get-IGAdLapsSchemaData {
    Assert-IGCommand -Name 'Get-ADObject' -Module 'ActiveDirectory (RSAT)'
    $schemaNamingContext = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
    Get-ADObject -SearchBase $schemaNamingContext -LDAPFilter $script:IGLapsSchemaFilter `
        -Properties 'lDAPDisplayName' -ErrorAction Stop |
        ForEach-Object { [string]$_.lDAPDisplayName }
}

function Resolve-IGAdGroupTarget {
    <#
    .SYNOPSIS
        Resolves a protected group definition to an SID + server, using SIDs to stay language independent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Group,
        [Parameter(Mandatory)] [object] $Domain,
        [Parameter(Mandatory)] [object] $RootDomain
    )

    if ($Group.ContainsKey('Sid')) {
        return @{ Sid = $Group.Sid; Server = [string]$Domain.DNSRoot }
    }

    $owner = if ($Group.ForestRoot) { $RootDomain } else { $Domain }
    @{ Sid = ('{0}-{1}' -f $owner.DomainSID, $Group.Rid); Server = [string]$owner.DNSRoot }
}

function Get-IGAdForestRootDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Domain
    )

    $rootName = [string](Get-ADForest -ErrorAction Stop).RootDomain
    if ($rootName -eq [string]$Domain.DNSRoot) {
        return $Domain
    }
    Get-ADDomain -Identity $rootName -Server $rootName -ErrorAction Stop
}

function Get-IGAdPrivilegedMemberData {
    <#
    .SYNOPSIS
        Returns one record per (protected group, recursive member) pair.
    #>
    Assert-IGCommand -Name 'Get-ADGroupMember' -Module 'ActiveDirectory (RSAT)'
    $domain = Get-ADDomain -ErrorAction Stop
    $rootDomain = Get-IGAdForestRootDomain -Domain $domain

    foreach ($group in $script:IGPrivilegedAdGroups) {
        $target = Resolve-IGAdGroupTarget -Group $group -Domain $domain -RootDomain $rootDomain
        $members = @(Get-ADGroupMember -Identity $target.Sid -Server $target.Server -Recursive -ErrorAction Stop)

        foreach ($member in $members) {
            [pscustomobject]@{
                Group             = $group.Name
                IsReported        = [bool]$group.Reported
                SamAccountName    = [string]$member.SamAccountName
                ObjectClass       = [string]$member.objectClass
                DistinguishedName = [string]$member.distinguishedName
            }
        }
    }
}
