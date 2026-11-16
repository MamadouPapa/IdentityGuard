BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $IGTestModulePath -Force
}

AfterAll {
    Remove-Module IdentityGuard -Force -ErrorAction SilentlyContinue
}

Describe 'AD-001 krbtgt password age' {
    It 'flags a krbtgt password older than 180 days' {
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'krbtgt' @{ Enabled = $false; PasswordLastSet = (Get-Date).AddDays(-400) }
            New-IGTestAdUser 'user01'
        }
        $finding = Invoke-IGTestCheck -Id 'AD-001'
        $finding.Status | Should -Be 'À corriger'
        $finding.Severity | Should -Be 'Élevée'
        $finding.Count | Should -Be 1
        $finding.Items[0].Name | Should -Be 'krbtgt'
    }

    It 'is compliant when the password was changed recently' {
        Mock Get-ADUser -ModuleName IdentityGuard { New-IGTestAdUser 'krbtgt' @{ PasswordLastSet = (Get-Date).AddDays(-30) } }
        (Invoke-IGTestCheck -Id 'AD-001').Status | Should -Be 'Conforme'
    }

    It 'also checks RODC krbtgt_* accounts' {
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'krbtgt' @{ PasswordLastSet = (Get-Date).AddDays(-30) }
            New-IGTestAdUser 'krbtgt_12345' @{ PasswordLastSet = (Get-Date).AddDays(-365) }
        }
        $finding = Invoke-IGTestCheck -Id 'AD-001'
        $finding.Count | Should -Be 1
        $finding.Items[0].Name | Should -Be 'krbtgt_12345'
    }

    It 'is reported as not executed when krbtgt cannot be found' {
        Mock Get-ADUser -ModuleName IdentityGuard { New-IGTestAdUser 'user01' }
        $finding = Invoke-IGTestCheckSafe -Id 'AD-001'
        $finding.Status | Should -Be 'Non exécuté'
        $finding.Severity | Should -Be 'Info'
    }
}

Describe 'AD-002 PasswordNeverExpires' {
    It 'counts only enabled accounts with PasswordNeverExpires' {
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'svc_app' @{ PasswordNeverExpires = $true }
            New-IGTestAdUser 'old_svc' @{ PasswordNeverExpires = $true; Enabled = $false }
            New-IGTestAdUser 'user01'
        }
        $finding = Invoke-IGTestCheck -Id 'AD-002'
        $finding.Count | Should -Be 1
        $finding.Items[0].Name | Should -Be 'svc_app'
        $finding.Severity | Should -Be 'Moyenne'
    }
}

Describe 'AD-003 inactive accounts' {
    It 'flags enabled accounts inactive for more than 90 days or never used' {
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'active'
            New-IGTestAdUser 'stale' @{ lastLogonTimestamp = (Get-Date).AddDays(-120).ToFileTime() }
            New-IGTestAdUser 'never_old' @{ lastLogonTimestamp = $null; whenCreated = (Get-Date).AddDays(-200) }
            New-IGTestAdUser 'never_new' @{ lastLogonTimestamp = $null; whenCreated = (Get-Date).AddDays(-10) }
            New-IGTestAdUser 'disabled_stale' @{ Enabled = $false; lastLogonTimestamp = (Get-Date).AddDays(-300).ToFileTime() }
        }
        $finding = Invoke-IGTestCheck -Id 'AD-003'
        $finding.Count | Should -Be 2
        @($finding.Items.Name) | Should -Contain 'stale'
        @($finding.Items.Name) | Should -Contain 'never_old'
        ($finding.Items | Where-Object Name -EQ 'never_old').Detail | Should -BeLike 'Jamais connecté*'
    }
}

Describe 'AD-004 privileged group members' {
    BeforeEach {
        Mock Get-ADDomain -ModuleName IdentityGuard { [pscustomobject]@{ DNSRoot = 'corp.contoso.example'; DomainSID = 'S-1-5-21-1-2-3' } }
        Mock Get-ADForest -ModuleName IdentityGuard { [pscustomobject]@{ RootDomain = 'corp.contoso.example' } }
    }

    It 'deduplicates members across groups, resolves groups by SID and is compliant under 5 members' {
        Mock Get-ADGroupMember -ModuleName IdentityGuard {
            switch ($Identity) {
                'S-1-5-21-1-2-3-512' { New-IGTestMember 'Administrator'; New-IGTestMember 'adm01'; New-IGTestMember 'adm02' }
                'S-1-5-32-544' { New-IGTestMember 'Administrator' }
                'S-1-5-32-551' { New-IGTestMember 'backup01' }
            }
        }
        $finding = Invoke-IGTestCheck -Id 'AD-004'
        $finding.Count | Should -Be 3
        $finding.Status | Should -Be 'Conforme'
        ($finding.Items | Where-Object Name -EQ 'Administrator').Detail | Should -BeLike '*Administrators*Domain Admins*'
        @($finding.Items.Name) | Should -Not -Contain 'backup01'
        Should -Invoke Get-ADGroupMember -ModuleName IdentityGuard -Times 8 -Exactly
    }

    It 'fails with Moyenne severity above 5 privileged accounts' {
        Mock Get-ADGroupMember -ModuleName IdentityGuard {
            if ($Identity -eq 'S-1-5-21-1-2-3-512') { 1..7 | ForEach-Object { New-IGTestMember ('adm{0:00}' -f $_) } }
        }
        $finding = Invoke-IGTestCheck -Id 'AD-004'
        $finding.Count | Should -Be 7
        $finding.Status | Should -Be 'À corriger'
        $finding.Severity | Should -Be 'Moyenne'
    }
}

Describe 'AD-005 AS-REP roasting' {
    It 'flags accounts without Kerberos pre-authentication with Élevée severity' {
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'legacy' @{ DoesNotRequirePreAuth = $true }
            New-IGTestAdUser 'user01'
        }
        $finding = Invoke-IGTestCheck -Id 'AD-005'
        $finding.Count | Should -Be 1
        $finding.Severity | Should -Be 'Élevée'
    }

    It 'escalates to Critique when a privileged account is affected' {
        Mock Get-ADUser -ModuleName IdentityGuard { New-IGTestAdUser 'adm' @{ DoesNotRequirePreAuth = $true; AdminCount = 1 } }
        (Invoke-IGTestCheck -Id 'AD-005').Severity | Should -Be 'Critique'
    }
}

Describe 'AD-006 Kerberoasting' {
    It 'flags enabled user accounts with an SPN and ignores krbtgt' {
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'krbtgt' @{ ServicePrincipalName = @('kadmin/changepw') }
            New-IGTestAdUser 'svc_sql' @{ ServicePrincipalName = @('MSSQLSvc/sql01:1433') }
            New-IGTestAdUser 'svc_off' @{ ServicePrincipalName = @('HTTP/web01'); Enabled = $false }
            New-IGTestAdUser 'user01' @{ ServicePrincipalName = $null }
        }
        $finding = Invoke-IGTestCheck -Id 'AD-006'
        $finding.Count | Should -Be 1
        $finding.Items[0].Name | Should -Be 'svc_sql'
        $finding.Items[0].Detail | Should -BeLike '*MSSQLSvc/sql01:1433*'
        $finding.Severity | Should -Be 'Élevée'
    }

    It 'escalates to Critique for a privileged service account' {
        Mock Get-ADUser -ModuleName IdentityGuard { New-IGTestAdUser 'svc_backup' @{ ServicePrincipalName = @('Backup/bkp01'); AdminCount = 1 } }
        (Invoke-IGTestCheck -Id 'AD-006').Severity | Should -Be 'Critique'
    }
}

Describe 'AD-007 unconstrained delegation' {
    It 'flags enabled non-DC computers trusted for delegation' {
        Mock Get-ADComputer -ModuleName IdentityGuard {
            New-IGTestComputer 'DC01' -PrimaryGroupId 516 -Trusted $true
            New-IGTestComputer 'RODC01' -PrimaryGroupId 521 -Trusted $true
            New-IGTestComputer 'SRV-APP01' -Trusted $true
            New-IGTestComputer 'SRV-OLD01' -Trusted $true -Enabled $false
            New-IGTestComputer 'WKS-01'
        }
        $finding = Invoke-IGTestCheck -Id 'AD-007'
        $finding.Count | Should -Be 1
        $finding.Items[0].Name | Should -Be 'SRV-APP01'
        $finding.Severity | Should -Be 'Critique'
    }
}

Describe 'AD-008 AdminCount orphans' {
    It 'flags adminCount=1 accounts that are not in any protected group' {
        Mock Get-ADDomain -ModuleName IdentityGuard { [pscustomobject]@{ DNSRoot = 'corp.contoso.example'; DomainSID = 'S-1-5-21-1-2-3' } }
        Mock Get-ADForest -ModuleName IdentityGuard { [pscustomobject]@{ RootDomain = 'corp.contoso.example' } }
        Mock Get-ADGroupMember -ModuleName IdentityGuard {
            if ($Identity -eq 'S-1-5-21-1-2-3-512') { New-IGTestMember 'adm01' }
            if ($Identity -eq 'S-1-5-32-551') { New-IGTestMember 'backup01' }
        }
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'adm01' @{ AdminCount = 1 }
            New-IGTestAdUser 'backup01' @{ AdminCount = 1 }
            New-IGTestAdUser 'ex_admin' @{ AdminCount = 1 }
            New-IGTestAdUser 'krbtgt' @{ AdminCount = 1; Enabled = $false }
            New-IGTestAdUser 'user01'
        }
        $finding = Invoke-IGTestCheck -Id 'AD-008'
        $finding.Count | Should -Be 1
        $finding.Items[0].Name | Should -Be 'ex_admin'
    }
}

Describe 'AD-009 PASSWD_NOTREQD' {
    It 'flags enabled accounts that do not require a password' {
        Mock Get-ADUser -ModuleName IdentityGuard {
            New-IGTestAdUser 'user06' @{ PasswordNotRequired = $true }
            New-IGTestAdUser 'Guest' @{ PasswordNotRequired = $true; Enabled = $false }
            New-IGTestAdUser 'user01'
        }
        $finding = Invoke-IGTestCheck -Id 'AD-009'
        $finding.Count | Should -Be 1
        $finding.Items[0].Name | Should -Be 'user06'
        $finding.Severity | Should -Be 'Élevée'
    }
}

Describe 'AD-010 LAPS presence' {
    BeforeEach {
        Mock Get-ADRootDSE -ModuleName IdentityGuard { [pscustomobject]@{ schemaNamingContext = 'CN=Schema,CN=Configuration,DC=corp,DC=contoso,DC=example' } }
        Mock Get-ADComputer -ModuleName IdentityGuard {
            New-IGTestComputer 'DC01' -PrimaryGroupId 516
            New-IGTestComputer 'SRV-01'
            New-IGTestComputer 'WKS-01'
        }
    }

    It 'is compliant when a LAPS attribute exists in the schema' {
        Mock Get-ADObject -ModuleName IdentityGuard { [pscustomobject]@{ lDAPDisplayName = 'msLAPS-Password' } }
        $finding = Invoke-IGTestCheck -Id 'AD-010'
        $finding.Status | Should -Be 'Conforme'
        $finding.Note | Should -BeLike '*msLAPS-Password*'
    }

    It 'fails and lists non-DC computers when LAPS is absent' {
        Mock Get-ADObject -ModuleName IdentityGuard { }
        $finding = Invoke-IGTestCheck -Id 'AD-010'
        $finding.Status | Should -Be 'À corriger'
        $finding.Count | Should -Be 2
        @($finding.Items.Name) | Should -Not -Contain 'DC01'
    }
}

Describe 'AD checks without the ActiveDirectory module or permission' {
    It 'reports Info "Contrôle non exécuté" when the AD query fails' {
        Mock Get-ADUser -ModuleName IdentityGuard { throw 'Access is denied' }
        $finding = Invoke-IGTestCheckSafe -Id 'AD-002'
        $finding.Severity | Should -Be 'Info'
        $finding.Status | Should -Be 'Non exécuté'
        $finding.Note | Should -BeLike 'Contrôle non exécuté*Access is denied*'
    }
}
