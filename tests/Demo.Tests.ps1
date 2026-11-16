BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $IGTestModulePath -Force
}

AfterAll {
    Remove-Module IdentityGuard -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-IdentityGuard -DemoMode' {
    BeforeAll {
        $script:ReportFile = Join-Path $TestDrive 'demo-report.html'
        $script:Result = Invoke-IdentityGuard -DemoMode -OutputPath $script:ReportFile
    }

    It 'writes the HTML report to the requested path' {
        $Result.ReportPath | Should -Be $ReportFile
        Test-Path -LiteralPath $ReportFile | Should -BeTrue
        Get-Content -LiteralPath $ReportFile -Raw -Encoding UTF8 | Should -Match 'MODE DÉMO'
    }

    It 'runs all 16 checks from fixtures without any directory or tenant' {
        $Result.Findings.Count | Should -Be 16
        $notRun = @($Result.Findings | Where-Object Status -EQ 'Non exécuté')
        $notRun.Count | Should -Be 1
        $notRun[0].Id | Should -Be 'ENT-006'
        $notRun[0].Note | Should -BeLike 'Contrôle non exécuté*P1*'
    }

    It 'produces the expected demo findings' {
        $byId = @{}
        foreach ($finding in $Result.Findings) { $byId[$finding.Id] = $finding }

        $byId['AD-001'].Status | Should -Be 'À corriger'
        $byId['AD-006'].Severity | Should -Be 'Critique'
        $byId['AD-007'].Count | Should -Be 2
        $byId['AD-008'].Count | Should -Be 2
        $byId['ENT-001'].Severity | Should -Be 'Critique'
        $byId['ENT-002'].Count | Should -Be 6
        $byId['ENT-003'].Count | Should -Be 2
        $byId['ENT-004'].Status | Should -Be 'Conforme'
        $byId['ENT-005'].Count | Should -Be 4
    }

    It 'returns a score between 0 and 100 with a grade' {
        $Result.Score | Should -BeGreaterOrEqual 0
        $Result.Score | Should -BeLessOrEqual 100
        $Result.Grade | Should -BeIn @('A', 'B', 'C', 'D', 'E')
    }
}

Describe 'Invoke-IdentityGuard options' {
    It 'limits the run to the requested scope' {
        $result = Invoke-IdentityGuard -DemoMode -Scope AD -OutputPath (Join-Path $TestDrive 'ad.html')
        $result.Findings.Count | Should -Be 10
        @($result.Findings | Where-Object Category -NE 'Active Directory').Count | Should -Be 0
    }

    It 'creates a timestamped file when OutputPath is a folder' {
        $folder = Join-Path $TestDrive 'out'
        New-Item -Path $folder -ItemType Directory | Out-Null
        $result = Invoke-IdentityGuard -DemoMode -Scope Entra -OutputPath $folder
        Split-Path -Path $result.ReportPath -Parent | Should -Be $folder
        Split-Path -Path $result.ReportPath -Leaf | Should -Match '^IdentityGuard-Report-\d{8}-\d{6}\.html$'
    }

    It 'does not crash and reports every check as not run outside a domain without demo mode' {
        Mock Get-ADUser -ModuleName IdentityGuard { throw 'Unable to find a default server with Active Directory Web Services running.' }
        Mock Get-ADComputer -ModuleName IdentityGuard { throw 'Unable to find a default server with Active Directory Web Services running.' }
        Mock Get-ADDomain -ModuleName IdentityGuard { throw 'Unable to find a default server with Active Directory Web Services running.' }
        Mock Get-ADRootDSE -ModuleName IdentityGuard { throw 'Unable to find a default server with Active Directory Web Services running.' }
        $result = Invoke-IdentityGuard -Scope AD -OutputPath (Join-Path $TestDrive 'offline.html')
        @($result.Findings | Where-Object Status -EQ 'Non exécuté').Count | Should -Be 10
        Test-Path -LiteralPath $result.ReportPath | Should -BeTrue
    }
}
