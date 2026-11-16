# Demo data provider: serves synthetic fixtures (Data/demo-fixtures.json) shaped like live sources.
# Properties named '<Name>DaysAgo' become '<Name>' DateTime values relative to now (negative = future),
# so the demo report stays realistic whatever the date.

function ConvertFrom-IGDemoValue {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Value,
        [Parameter(Mandatory)] [datetime] $Now
    )

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $result = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.Name -match '^(?<name>.+)DaysAgo$') {
                $name = $Matches['name']
                $result[$name] = if ($null -eq $property.Value) { $null } else { $Now.AddDays(-[double]$property.Value) }
            }
            else {
                $result[$property.Name] = ConvertFrom-IGDemoValue -Value $property.Value -Now $Now
            }
        }
        return [pscustomobject]$result
    }

    if ($Value -is [System.Array]) {
        $converted = @($Value | ForEach-Object { ConvertFrom-IGDemoValue -Value $_ -Now $Now })
        return , $converted
    }

    $Value
}

function Get-IGDemoFixture {
    [CmdletBinding()]
    param()

    if ($null -eq $script:IGDemoFixture) {
        $path = Join-Path $script:IGModuleRoot 'Data/demo-fixtures.json'
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Demo fixture file not found: $path"
        }
        $script:IGDemoFixture = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    $script:IGDemoFixture
}

function Get-IGDemoSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    $fixture = Get-IGDemoFixture
    $property = $fixture.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "Demo fixture has no data for source '$Name'."
    }

    $raw = $property.Value
    if ($raw -is [System.Management.Automation.PSCustomObject] -and $raw.PSObject.Properties['_simulatedError']) {
        throw [string]$raw._simulatedError
    }

    $converted = ConvertFrom-IGDemoValue -Value $raw -Now (Get-Date)
    $converted
}
