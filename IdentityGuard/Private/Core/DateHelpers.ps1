function ConvertTo-IGDateTime {
    <#
    .SYNOPSIS
        Normalizes AD/Graph date values (FileTime Int64, DateTime, DateTimeOffset, string) to DateTime or $null.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    if ($Value -is [datetimeoffset]) { return $Value.LocalDateTime }

    if ($Value -is [long] -or $Value -is [int]) {
        # 0 and Int64.MaxValue mean "never" in AD.
        if ($Value -le 0 -or $Value -eq [long]::MaxValue) { return $null }
        return [datetime]::FromFileTime([long]$Value)
    }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeLocal
    if ([datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }
    return $null
}

function Get-IGDaysSince {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [datetime] $Date
    )

    [int][math]::Floor(((Get-Date) - $Date).TotalDays)
}

function Format-IGDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [object] $Date
    )

    $value = ConvertTo-IGDateTime -Value $Date
    if ($null -eq $value) { return 'jamais' }
    $value.ToString('yyyy-MM-dd')
}

function Test-IGIsStale {
    <#
    .SYNOPSIS
        True when the last activity (or, if never active, the creation date) is older than $Days.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()] [object] $LastActivity,
        [AllowNull()] [object] $Created,
        [Parameter(Mandatory)] [int] $Days
    )

    $last = ConvertTo-IGDateTime -Value $LastActivity
    if ($null -ne $last) { return (Get-IGDaysSince -Date $last) -gt $Days }

    $createdOn = ConvertTo-IGDateTime -Value $Created
    if ($null -eq $createdOn) { return $true }
    (Get-IGDaysSince -Date $createdOn) -gt $Days
}

function Get-IGActivityDetail {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [object] $LastActivity,
        [AllowNull()] [object] $Created
    )

    $last = ConvertTo-IGDateTime -Value $LastActivity
    if ($null -ne $last) {
        return ('Dernière connexion : {0} (il y a {1} jours)' -f (Format-IGDate $last), (Get-IGDaysSince -Date $last))
    }
    'Jamais connecté (créé le {0})' -f (Format-IGDate $Created)
}
