BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $IGTestModulePath -Force
}

AfterAll {
    Remove-Module IdentityGuard -Force -ErrorAction SilentlyContinue
}

Describe 'Entra ID checks' {
    BeforeEach {
        Mock Get-MgContext -ModuleName IdentityGuard { [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000000' } }
    }

    Describe 'Graph connection' {
        It 'reports the check as not executed when no Graph session exists' {
            Mock Get-MgContext -ModuleName IdentityGuard { $null }
            $finding = Invoke-IGTestCheckSafe -Id 'ENT-001'
            $finding.Status | Should -Be 'Non exécuté'
            $finding.Note | Should -BeLike '*Connect-MgGraph*'
        }
    }

    Describe 'ENT-001 MFA registration' {
        It 'flags unregistered members and escalates to Critique for administrators' {
            Mock Get-MgReportAuthenticationMethodUserRegistrationDetail -ModuleName IdentityGuard {
                [pscustomobject]@{ UserPrincipalName = 'admin02@contoso.example'; UserType = 'member'; IsAdmin = $true; IsMfaRegistered = $false }
                [pscustomobject]@{ UserPrincipalName = 'user02@contoso.example'; UserType = 'member'; IsAdmin = $false; IsMfaRegistered = $false }
                [pscustomobject]@{ UserPrincipalName = 'user01@contoso.example'; UserType = 'member'; IsAdmin = $false; IsMfaRegistered = $true }
                [pscustomobject]@{ UserPrincipalName = 'guest01#EXT#@contoso.example'; UserType = 'guest'; IsAdmin = $false; IsMfaRegistered = $false }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-001'
            $finding.Count | Should -Be 2
            $finding.Severity | Should -Be 'Critique'
            @($finding.Items.Name) | Should -Not -Contain 'guest01#EXT#@contoso.example'
        }

        It 'uses Élevée severity when no administrator is affected' {
            Mock Get-MgReportAuthenticationMethodUserRegistrationDetail -ModuleName IdentityGuard {
                [pscustomobject]@{ UserPrincipalName = 'user02@contoso.example'; UserType = 'member'; IsAdmin = $false; IsMfaRegistered = $false }
            }
            (Invoke-IGTestCheck -Id 'ENT-001').Severity | Should -Be 'Élevée'
        }
    }

    Describe 'ENT-002 permanent privileged roles' {
        BeforeEach {
            Mock Get-MgUser -ModuleName IdentityGuard {
                New-IGTestEntraUser -Id 'u1' -Upn 'admin01@contoso.example'
                New-IGTestEntraUser -Id 'u2' -Upn 'admin02@contoso.example'
            }
        }

        It 'counts only permanent assignments of privileged roles' {
            Mock Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -ModuleName IdentityGuard {
                [pscustomobject]@{ PrincipalId = 'u1'; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; AssignmentType = 'Assigned'; EndDateTime = $null }
                [pscustomobject]@{ PrincipalId = 'u2'; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; AssignmentType = 'Assigned'; EndDateTime = $null }
                [pscustomobject]@{ PrincipalId = 'u3'; RoleDefinitionId = '194ae4cb-b126-40b2-bd5b-6091b380977d'; AssignmentType = 'Assigned'; EndDateTime = $null }
                [pscustomobject]@{ PrincipalId = 'u4'; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; AssignmentType = 'Activated'; EndDateTime = (Get-Date).AddHours(4) }
                [pscustomobject]@{ PrincipalId = 'u5'; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; AssignmentType = 'Assigned'; EndDateTime = (Get-Date).AddDays(30) }
                [pscustomobject]@{ PrincipalId = 'u6'; RoleDefinitionId = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'; AssignmentType = 'Assigned'; EndDateTime = $null }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-002'
            $finding.Count | Should -Be 3
            $finding.Status | Should -Be 'À corriger'
            $finding.Severity | Should -Be 'Moyenne'
            @($finding.Items.Name) | Should -Contain 'admin01@contoso.example'
            @($finding.Items.Name) | Should -Contain 'u3'
        }

        It 'uses Élevée severity above 4 permanent Global Administrators' {
            Mock Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -ModuleName IdentityGuard {
                1..5 | ForEach-Object { [pscustomobject]@{ PrincipalId = "u$_"; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; AssignmentType = 'Assigned'; EndDateTime = $null } }
            }
            (Invoke-IGTestCheck -Id 'ENT-002').Severity | Should -Be 'Élevée'
        }

        It 'falls back to direct role assignments when PIM is unavailable' {
            Mock Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -ModuleName IdentityGuard { throw 'AadPremiumLicenseRequired' }
            Mock Get-MgRoleManagementDirectoryRoleAssignment -ModuleName IdentityGuard {
                [pscustomobject]@{ PrincipalId = 'u1'; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10' }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-002'
            $finding.Count | Should -Be 1
            $finding.Status | Should -Be 'Conforme'
            $finding.Note | Should -BeLike '*Direct*'
            Should -Invoke Get-MgRoleManagementDirectoryRoleAssignment -ModuleName IdentityGuard -Times 1 -Exactly
        }
    }

    Describe 'ENT-003 stale guests' {
        It 'uses signInActivity when available' {
            Mock Get-MgUser -ModuleName IdentityGuard -ParameterFilter { $Property -contains 'signInActivity' } {
                New-IGTestEntraUser -Id 'g1' -Upn 'old_guest#EXT#' -UserType 'Guest' -Property @{ SignInActivity = (New-IGTestSignIn -DaysAgo 200) }
                New-IGTestEntraUser -Id 'g2' -Upn 'recent_guest#EXT#' -UserType 'Guest' -Property @{ SignInActivity = (New-IGTestSignIn -DaysAgo 5) }
                New-IGTestEntraUser -Id 'm1' -Upn 'member@contoso.example' -Property @{ SignInActivity = (New-IGTestSignIn -DaysAgo 300) }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-003'
            $finding.Count | Should -Be 1
            $finding.Items[0].Name | Should -Be 'old_guest#EXT#'
            $finding.Note | Should -BeLike '2 invité*signInActivity*'
        }

        It 'falls back to long-pending invitations without Entra ID P1' {
            Mock Get-MgUser -ModuleName IdentityGuard -ParameterFilter { $Property -contains 'signInActivity' } {
                throw "Neither tenant is B2C or tenant doesn't have premium license"
            }
            Mock Get-MgUser -ModuleName IdentityGuard {
                New-IGTestEntraUser -Id 'g1' -Upn 'pending_old#EXT#' -UserType 'Guest' -Property @{ ExternalUserState = 'PendingAcceptance'; CreatedDateTime = (Get-Date).AddDays(-60) }
                New-IGTestEntraUser -Id 'g2' -Upn 'pending_new#EXT#' -UserType 'Guest' -Property @{ ExternalUserState = 'PendingAcceptance'; CreatedDateTime = (Get-Date).AddDays(-3) }
                New-IGTestEntraUser -Id 'g3' -Upn 'accepted#EXT#' -UserType 'Guest' -Property @{ ExternalUserState = 'Accepted' }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-003'
            $finding.Count | Should -Be 1
            $finding.Items[0].Name | Should -Be 'pending_old#EXT#'
            $finding.Note | Should -BeLike '*P1*'
        }
    }

    Describe 'ENT-004 Security Defaults / Conditional Access' {
        It 'is Critique when Security Defaults are off and no CA policy is enabled' {
            Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ModuleName IdentityGuard { [pscustomobject]@{ IsEnabled = $false } }
            Mock Get-MgIdentityConditionalAccessPolicy -ModuleName IdentityGuard {
                [pscustomobject]@{ DisplayName = 'CA-Report'; State = 'enabledForReportingButNotEnforced' }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-004'
            $finding.Status | Should -Be 'À corriger'
            $finding.Severity | Should -Be 'Critique'
            $finding.Count | Should -Be 0
        }

        It 'is compliant with at least one enabled CA policy' {
            Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ModuleName IdentityGuard { [pscustomobject]@{ IsEnabled = $false } }
            Mock Get-MgIdentityConditionalAccessPolicy -ModuleName IdentityGuard {
                [pscustomobject]@{ DisplayName = 'CA-MFA'; State = 'enabled' }
                [pscustomobject]@{ DisplayName = 'CA-Off'; State = 'disabled' }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-004'
            $finding.Status | Should -Be 'Conforme'
            $finding.Count | Should -Be 1
        }

        It 'is compliant with Security Defaults even when CA cannot be read' {
            Mock Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ModuleName IdentityGuard { [pscustomobject]@{ IsEnabled = $true } }
            Mock Get-MgIdentityConditionalAccessPolicy -ModuleName IdentityGuard { throw 'Forbidden' }
            $finding = Invoke-IGTestCheck -Id 'ENT-004'
            $finding.Status | Should -Be 'Conforme'
            $finding.Note | Should -BeLike '*Accès conditionnel impossible*Forbidden*'
        }
    }

    Describe 'ENT-005 application credentials' {
        It 'flags expired and soon-to-expire secrets and certificates' {
            Mock Get-MgApplication -ModuleName IdentityGuard {
                [pscustomobject]@{
                    DisplayName         = 'App-A'
                    PasswordCredentials = @([pscustomobject]@{ DisplayName = 'old'; EndDateTime = (Get-Date).AddDays(-3) })
                    KeyCredentials      = @([pscustomobject]@{ DisplayName = 'cert'; EndDateTime = (Get-Date).AddDays(10) })
                }
                [pscustomobject]@{
                    DisplayName         = 'App-B'
                    PasswordCredentials = @([pscustomobject]@{ DisplayName = 'ok'; EndDateTime = (Get-Date).AddDays(100) })
                    KeyCredentials      = $null
                }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-005'
            $finding.Count | Should -Be 2
            @($finding.Items.Name) | Should -Not -Contain 'App-B'
            @($finding.Items.Detail) -join '|' | Should -BeLike '*Secret*expiré*'
            @($finding.Items.Detail) -join '|' | Should -BeLike '*Certificat*expire le*'
        }
    }

    Describe 'ENT-006 stale member accounts' {
        It 'flags enabled members without sign-in for more than 90 days' {
            Mock Get-MgUser -ModuleName IdentityGuard {
                New-IGTestEntraUser -Id 'm1' -Upn 'stale@contoso.example' -Property @{ SignInActivity = (New-IGTestSignIn -DaysAgo 120) }
                New-IGTestEntraUser -Id 'm2' -Upn 'active@contoso.example' -Property @{ SignInActivity = (New-IGTestSignIn -DaysAgo 2) }
                New-IGTestEntraUser -Id 'm3' -Upn 'never@contoso.example' -Property @{ SignInActivity = (New-IGTestSignIn -DaysAgo $null); CreatedDateTime = (Get-Date).AddDays(-200) }
                New-IGTestEntraUser -Id 'm4' -Upn 'disabled@contoso.example' -Property @{ AccountEnabled = $false; SignInActivity = (New-IGTestSignIn -DaysAgo 300) }
                New-IGTestEntraUser -Id 'g1' -Upn 'guest#EXT#' -UserType 'Guest' -Property @{ SignInActivity = (New-IGTestSignIn -DaysAgo 300) }
            }
            $finding = Invoke-IGTestCheck -Id 'ENT-006'
            $finding.Count | Should -Be 2
            @($finding.Items.Name) | Should -Contain 'stale@contoso.example'
            @($finding.Items.Name) | Should -Contain 'never@contoso.example'
        }

        It 'considers non-interactive sign-ins as activity' {
            Mock Get-MgUser -ModuleName IdentityGuard {
                $activity = [pscustomobject]@{ LastSignInDateTime = (Get-Date).AddDays(-200); LastNonInteractiveSignInDateTime = (Get-Date).AddDays(-1) }
                New-IGTestEntraUser -Id 'm1' -Upn 'svc@contoso.example' -Property @{ SignInActivity = $activity }
            }
            (Invoke-IGTestCheck -Id 'ENT-006').Status | Should -Be 'Conforme'
        }

        It 'is reported as not executed without Entra ID P1' {
            Mock Get-MgUser -ModuleName IdentityGuard { throw "Neither tenant is B2C or tenant doesn't have premium license" }
            $finding = Invoke-IGTestCheckSafe -Id 'ENT-006'
            $finding.Status | Should -Be 'Non exécuté'
            $finding.Severity | Should -Be 'Info'
            $finding.Note | Should -BeLike 'Contrôle non exécuté*P1*'
        }
    }
}
