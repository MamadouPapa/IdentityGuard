<#
.SYNOPSIS
    Runs the Pester test suite, regenerates docs/demo-report.html and, when Chrome is available,
    captures docs/demo-report.png (headless).

.EXAMPLE
    pwsh ./scripts/Invoke-Validation.ps1 -InstallPester
#>
[CmdletBinding()]
param(
    [switch] $InstallPester,
    [switch] $SkipScreenshot
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Path $PSScriptRoot -Parent
$docs = Join-Path $root 'docs'
$minimumPester = [version]'5.5.0'

$pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester -or $pester.Version -lt $minimumPester) {
    if (-not $InstallPester) {
        throw "Pester $minimumPester+ is required. Re-run with -InstallPester or: Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck"
    }
    Install-Module -Name Pester -MinimumVersion $minimumPester -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module Pester -MinimumVersion $minimumPester

$configuration = New-PesterConfiguration
$configuration.Run.Path = Join-Path $root 'tests'
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $configuration
if ($result.FailedCount -gt 0) {
    throw "$($result.FailedCount) test(s) failed."
}

Import-Module (Join-Path $root 'IdentityGuard/IdentityGuard.psd1') -Force
$report = Invoke-IdentityGuard -DemoMode -OutputPath (Join-Path $docs 'demo-report.html')
Write-Host ("Demo report: {0} (score {1}/100, niveau {2})" -f $report.ReportPath, $report.Score, $report.Grade)

if ($SkipScreenshot) { return }

$chromeCandidates = @(
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    'C:\Program Files\Google\Chrome\Application\chrome.exe'
    'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
    '/usr/bin/google-chrome'
)
$chrome = $chromeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $chrome) {
    Write-Warning 'Google Chrome not found: screenshot skipped.'
    return
}

$png = Join-Path $docs 'demo-report.png'
$url = ([System.Uri](Resolve-Path -LiteralPath $report.ReportPath).Path).AbsoluteUri
& $chrome --headless=new --disable-gpu --hide-scrollbars --window-size=1280,1600 "--screenshot=$png" $url | Out-Null
Write-Host "Screenshot: $png"
