BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $IGTestModulePath -Force
}

AfterAll {
    Remove-Module IdentityGuard -Force -ErrorAction SilentlyContinue
}

Describe 'Module surface' {
    It 'exports only Invoke-IdentityGuard' {
        $commands = @(Get-Command -Module IdentityGuard)
        $commands.Count | Should -Be 1
        $commands[0].Name | Should -Be 'Invoke-IdentityGuard'
    }
}

Describe 'Check catalog' {
    It 'contains 10 AD checks and 6 Entra checks with unique ids' {
        InModuleScope IdentityGuard {
            @(Get-IGCheckDefinition -Scope AD).Count | Should -Be 10
            @(Get-IGCheckDefinition -Scope Entra).Count | Should -Be 6
            $ids = @(Get-IGCheckDefinition -Scope All | ForEach-Object { $_.Id })
            @($ids | Sort-Object -Unique).Count | Should -Be 16
        }
    }

    It 'points every check to an existing function with remediation and reference' {
        InModuleScope IdentityGuard {
            foreach ($definition in Get-IGCheckDefinition -Scope All) {
                Get-Command -Name $definition.Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because $definition.Id
                $definition.Remediation | Should -Not -BeNullOrEmpty
                $definition.Reference | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'references the expected MITRE ATT&CK techniques' {
        InModuleScope IdentityGuard {
            (Get-IGCheckDefinition -Id 'AD-005').Reference | Should -Match 'T1558\.004'
            (Get-IGCheckDefinition -Id 'AD-006').Reference | Should -Match 'T1558\.003'
            (Get-IGCheckDefinition -Id 'AD-003').Reference | Should -Match 'T1078'
        }
    }

    It 'throws on an unknown id' {
        InModuleScope IdentityGuard {
            { Get-IGCheckDefinition -Id 'XX-999' } | Should -Throw '*XX-999*'
        }
    }
}

Describe 'New-IGFinding' {
    It 'returns a compliant Info finding when there is no item' {
        InModuleScope IdentityGuard {
            $finding = New-IGFinding -Id 'AD-002' -Severity 'Moyenne' -Items @()
            $finding.Status | Should -Be 'Conforme'
            $finding.Severity | Should -Be 'Info'
            $finding.Count | Should -Be 0
        }
    }

    It 'returns a failing finding with the requested severity and uniform fields' {
        InModuleScope IdentityGuard {
            $items = @((New-IGItem -Name 'a' -Detail 'x'), (New-IGItem -Name 'b' -Detail 'y'))
            $finding = New-IGFinding -Id 'AD-002' -Severity 'Moyenne' -Items $items
            $finding.Status | Should -Be 'À corriger'
            $finding.Severity | Should -Be 'Moyenne'
            $finding.Count | Should -Be 2
            $finding.Category | Should -Be 'Active Directory'
            foreach ($field in 'Id', 'Category', 'Title', 'Severity', 'Count', 'Items', 'Remediation', 'Reference') {
                $finding.PSObject.Properties.Name | Should -Contain $field
            }
        }
    }

    It 'honours explicit IsCompliant and Count' {
        InModuleScope IdentityGuard {
            $finding = New-IGFinding -Id 'ENT-004' -Severity 'Critique' -Count 3 -IsCompliant $true
            $finding.Status | Should -Be 'Conforme'
            $finding.Count | Should -Be 3

            $failing = New-IGFinding -Id 'AD-010' -Severity 'Élevée' -Count 0 -IsCompliant $false
            $failing.Status | Should -Be 'À corriger'
            $failing.Severity | Should -Be 'Élevée'
        }
    }

    It 'ignores null items' {
        InModuleScope IdentityGuard {
            $finding = New-IGFinding -Id 'AD-002' -Severity 'Moyenne' -Items @($null, (New-IGItem -Name 'a'))
            $finding.Count | Should -Be 1
        }
    }
}

Describe 'Invoke-IGCheck error isolation' {
    It 'turns an exception into an Info "Contrôle non exécuté" finding' {
        InModuleScope IdentityGuard {
            function script:Test-IGBoom { throw 'boom' }
            $definition = [pscustomobject]@{ Id = 'AD-001'; Function = 'Test-IGBoom' }
            $finding = Invoke-IGCheck -Definition $definition
            $finding.Severity | Should -Be 'Info'
            $finding.Status | Should -Be 'Non exécuté'
            $finding.Note | Should -Be 'Contrôle non exécuté : boom'
        }
    }

    It 'promotes non-terminating errors' {
        InModuleScope IdentityGuard {
            function script:Test-IGSoftError { Write-Error 'soft failure'; New-IGFinding -Id 'AD-001' -Severity 'Élevée' }
            $finding = Invoke-IGCheck -Definition ([pscustomobject]@{ Id = 'AD-001'; Function = 'Test-IGSoftError' })
            $finding.Status | Should -Be 'Non exécuté'
            $finding.Note | Should -BeLike '*soft failure*'
        }
    }
}

Describe 'Source layer' {
    It 'reports a readable error when a cmdlet is missing' {
        InModuleScope IdentityGuard {
            { Assert-IGCommand -Name 'Get-IGDoesNotExist' -Module 'FakeModule' } | Should -Throw '*Get-IGDoesNotExist*FakeModule*'
        }
    }

    It 'collects each source only once per run' {
        Mock Get-ADUser -ModuleName IdentityGuard { New-IGTestAdUser 'user01' }
        InModuleScope IdentityGuard {
            $script:IGSourceCache = @{}
            $script:IGDemoMode = $false
            $null = Test-IGAdPasswordNeverExpires
            $null = Test-IGAdPasswordNotRequired
        }
        Should -Invoke Get-ADUser -ModuleName IdentityGuard -Times 1 -Exactly
    }

    It 'caches failures so every dependent check reports the same reason' {
        Mock Get-ADUser -ModuleName IdentityGuard { throw 'Unable to contact the server' }
        InModuleScope IdentityGuard {
            $script:IGSourceCache = @{}
            $script:IGDemoMode = $false
            $first = Invoke-IGCheck -Definition (Get-IGCheckDefinition -Id 'AD-002')
            $second = Invoke-IGCheck -Definition (Get-IGCheckDefinition -Id 'AD-009')
            $first.Note | Should -BeLike '*Unable to contact the server*'
            $second.Note | Should -Be $first.Note
        }
        Should -Invoke Get-ADUser -ModuleName IdentityGuard -Times 1 -Exactly
    }
}

Describe 'Date helpers' {
    It 'converts AD FileTime values and treats 0 / MaxValue as never' {
        InModuleScope IdentityGuard {
            $date = (Get-Date).AddDays(-5)
            (ConvertTo-IGDateTime -Value $date.ToFileTime()).Date | Should -Be $date.Date
            ConvertTo-IGDateTime -Value ([long]0) | Should -BeNullOrEmpty
            ConvertTo-IGDateTime -Value ([long]::MaxValue) | Should -BeNullOrEmpty
            ConvertTo-IGDateTime -Value $null | Should -BeNullOrEmpty
        }
    }

    It 'parses ISO strings and passes DateTime through' {
        InModuleScope IdentityGuard {
            (ConvertTo-IGDateTime -Value '2025-01-15T10:00:00').Year | Should -Be 2025
            $now = Get-Date
            ConvertTo-IGDateTime -Value $now | Should -Be $now
        }
    }

    It 'evaluates staleness from last activity, then creation date' {
        InModuleScope IdentityGuard {
            Test-IGIsStale -LastActivity (Get-Date).AddDays(-100) -Created $null -Days 90 | Should -BeTrue
            Test-IGIsStale -LastActivity (Get-Date).AddDays(-10) -Created $null -Days 90 | Should -BeFalse
            Test-IGIsStale -LastActivity $null -Created (Get-Date).AddDays(-10) -Days 90 | Should -BeFalse
            Test-IGIsStale -LastActivity $null -Created (Get-Date).AddDays(-200) -Days 90 | Should -BeTrue
        }
    }
}
