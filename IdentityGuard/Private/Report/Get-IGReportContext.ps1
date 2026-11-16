function Get-IGReportContext {
    <#
    .SYNOPSIS
        Collects report metadata (audited domain / tenant names, date, scope). Never fails the run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('AD', 'Entra', 'All')] [string] $Scope,
        [switch] $IsDemo
    )

    $targets = @()
    if ($Scope -ne 'Entra') {
        $domain = Get-IGOptionalSource -Name 'ADDomain'
        if ($domain) { $targets += 'AD : {0}' -f @($domain)[0].DNSRoot }
    }
    if ($Scope -ne 'AD') {
        $organization = Get-IGOptionalSource -Name 'EntraOrganization'
        if ($organization) { $targets += 'Entra ID : {0}' -f @($organization)[0].DisplayName }
    }

    $scopeLabel = @{ AD = 'Active Directory'; Entra = 'Entra ID'; All = 'Active Directory + Entra ID' }[$Scope]

    [pscustomobject]@{
        Target      = $(if ($targets.Count -gt 0) { $targets -join ' · ' } else { 'Non déterminée' })
        Scope       = $scopeLabel
        GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        IsDemo      = [bool]$IsDemo
        Version     = [string]$script:IGVersion
    }
}
