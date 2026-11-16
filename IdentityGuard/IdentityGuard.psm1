# IdentityGuard root module: loads private helpers first, then public entry points.

$script:IGModuleRoot = $PSScriptRoot
$script:IGVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'IdentityGuard.psd1')).ModuleVersion
$script:IGSourceCache = @{}
$script:IGDemoMode = $false
$script:IGDemoFixture = $null

$privateFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse)
$publicFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -Recurse)

foreach ($file in ($privateFiles + $publicFiles)) {
    try {
        . $file.FullName
    }
    catch {
        throw "IdentityGuard: unable to load '$($file.FullName)': $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function ($publicFiles | ForEach-Object { $_.BaseName })
