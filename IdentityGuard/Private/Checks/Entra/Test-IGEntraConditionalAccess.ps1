$script:IGCaStateLabel = @{
    'enabled'                           = 'Activée'
    'disabled'                          = 'Désactivée'
    'enabledForReportingButNotEnforced' = 'Rapport uniquement'
}

function Get-IGCaStateLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $State
    )

    if ($State -and $script:IGCaStateLabel.ContainsKey($State)) { return $script:IGCaStateLabel[$State] }
    [string]$State
}

function Test-IGEntraConditionalAccess {
    <#
    .SYNOPSIS
        ENT-004: flags tenants with neither Security Defaults nor any enabled Conditional Access policy.
    #>
    [CmdletBinding()]
    param()

    $securityDefaults = @(Get-IGSource -Name 'EntraSecurityDefaults') | Select-Object -First 1
    $isSecurityDefaultsOn = $null -ne $securityDefaults -and $securityDefaults.IsEnabled -eq $true

    $caError = $null
    try {
        $policies = @(Get-IGSource -Name 'EntraCAPolicies')
    }
    catch {
        $policies = @()
        $caError = $_.Exception.Message
    }

    $enabled = @($policies | Where-Object { [string]$_.State -eq 'enabled' })
    $items = foreach ($policy in $policies) {
        New-IGItem -Name ([string]$policy.DisplayName) -Detail (Get-IGCaStateLabel -State ([string]$policy.State))
    }

    $defaultsLabel = if ($isSecurityDefaultsOn) { 'activés' } else { 'désactivés' }
    $note = 'Paramètres de sécurité par défaut : {0} ; stratégies d''Accès conditionnel activées : {1} sur {2}.' -f $defaultsLabel, $enabled.Count, $policies.Count
    if ($caError) {
        $note += ' Lecture de l''Accès conditionnel impossible (licence P1 ou permission Policy.Read.All) : ' + $caError
    }

    New-IGFinding -Id 'ENT-004' -Severity 'Critique' -Items $items -Count $enabled.Count `
        -IsCompliant ($isSecurityDefaultsOn -or $enabled.Count -gt 0) -Note $note
}
