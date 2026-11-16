function Get-IGExpiringCredentialItem {
    <#
    .SYNOPSIS
        Emits one item per credential of $App that is expired or expires before $Limit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $App,
        [AllowEmptyCollection()] [object[]] $Credentials = @(),
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [datetime] $Limit
    )

    $now = Get-Date
    foreach ($credential in @($Credentials | Where-Object { $null -ne $_ })) {
        $end = ConvertTo-IGDateTime -Value $credential.EndDateTime
        if ($null -eq $end -or $end -ge $Limit) { continue }

        $label = if ($credential.DisplayName) { " « {0} »" -f $credential.DisplayName } else { '' }
        $detail = if ($end -lt $now) {
            '{0}{1} expiré le {2}' -f $Kind, $label, (Format-IGDate $end)
        }
        else {
            '{0}{1} expire le {2} (dans {3} jours)' -f $Kind, $label, (Format-IGDate $end), [int][math]::Ceiling(($end - $now).TotalDays)
        }
        New-IGItem -Name ([string]$App.DisplayName) -Detail $detail
    }
}

function Test-IGEntraAppCredentialExpiry {
    <#
    .SYNOPSIS
        ENT-005: app registration secrets and certificates expired or expiring within the threshold.
    #>
    [CmdletBinding()]
    param()

    $days = $script:IGThresholds.CredentialExpiryDays
    $limit = (Get-Date).AddDays($days)

    $items = foreach ($app in @(Get-IGSource -Name 'EntraApplications')) {
        Get-IGExpiringCredentialItem -App $app -Credentials @($app.PasswordCredentials) -Kind 'Secret' -Limit $limit
        Get-IGExpiringCredentialItem -App $app -Credentials @($app.KeyCredentials) -Kind 'Certificat' -Limit $limit
    }

    New-IGFinding -Id 'ENT-005' -Severity 'Moyenne' -Items $items -Note ("Fenêtre d'alerte : {0} jours." -f $days)
}
