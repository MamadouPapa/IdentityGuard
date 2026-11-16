BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $IGTestModulePath -Force
}

AfterAll {
    Remove-Module IdentityGuard -Force -ErrorAction SilentlyContinue
}

Describe 'HTML encoding' {
    It 'encodes markup characters' {
        InModuleScope IdentityGuard {
            ConvertTo-IGHtml '<script>alert("x")</script>' | Should -Be '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;'
            ConvertTo-IGHtml "O'Brien & Co" | Should -Be 'O&#39;Brien &amp; Co'
            ConvertTo-IGHtml $null | Should -Be ''
        }
    }

    It 'neutralizes hostile object names coming from directory data' {
        InModuleScope IdentityGuard {
            $item = New-IGItem -Name '<img src=x onerror=alert(1)>' -Detail '"><script>alert(2)</script>'
            $finding = New-IGFinding -Id 'AD-002' -Severity 'Moyenne' -Items @($item) -Note '<b>note</b>'
            $context = [pscustomobject]@{ Target = '<svg onload=alert(3)>'; Scope = 'AD'; GeneratedAt = 'now'; IsDemo = $false; Version = '1.0.0' }

            $html = ConvertTo-IGHtmlReport -Finding @($finding) -Context $context

            $html | Should -Not -Match '<script'
            $html | Should -Not -Match '<img'
            $html | Should -Not -Match '<svg'
            $html | Should -Not -Match '<b>note'
            $html | Should -Match ([regex]::Escape('&lt;img src=x onerror=alert(1)&gt;'))
            $html | Should -Match ([regex]::Escape('&quot;&gt;&lt;script&gt;alert(2)&lt;/script&gt;'))
            $html | Should -Match ([regex]::Escape('<title>IdentityGuard – &lt;svg onload=alert(3)&gt;</title>'))
        }
    }

    It 'only turns https URLs into links' {
        InModuleScope IdentityGuard {
            $linked = ConvertTo-IGLinkedHtml 'Voir https://learn.microsoft.com/a?b=1&c=2 ; javascript:alert(1)'
            $linked | Should -Match '<a href="https://learn\.microsoft\.com/a\?b=1&amp;c=2" rel="noopener noreferrer">'
            $linked | Should -Not -Match 'href="javascript'
        }
    }
}

Describe 'HTML report' {
    BeforeAll {
        $script:Html = InModuleScope IdentityGuard {
            $findings = @(
                (New-IGFinding -Id 'AD-007' -Severity 'Critique' -Items @(New-IGItem -Name 'SRV-APP01' -Detail 'x'))
                (New-IGFinding -Id 'AD-002' -Severity 'Moyenne' -Items @())
                (New-IGNotRunFinding -Id 'ENT-006' -Reason 'licence P1 requise')
            )
            $context = [pscustomobject]@{ Target = 'AD : corp.contoso.example'; Scope = 'AD'; GeneratedAt = '2026-01-01 10:00'; IsDemo = $true; Version = '1.0.0' }
            ConvertTo-IGHtmlReport -Finding $findings -Context $context
        }
    }

    It 'is a complete, self-contained document' {
        $Html | Should -Match '^<!DOCTYPE html>'
        $Html | Should -Match '<meta charset="utf-8">'
        $Html | Should -Match '<style>'
        $Html | Should -Not -Match '<link\s'
        $Html | Should -Not -Match '<script'
        # Reference links are allowed; loaded resources (src=, stylesheets, @import) are not.
        $Html | Should -Not -Match '\ssrc="'
        $Html | Should -Not -Match '@import'
    }

    It 'shows the demo badge, every finding and the not-run reason' {
        $Html | Should -Match 'MODE DÉMO'
        $Html | Should -Match 'id="f-ad-007"'
        $Html | Should -Match 'id="f-ad-002"'
        $Html | Should -Match 'Contrôle non exécuté : signInActivity indisponible \(licence Entra ID P1'
    }

    It 'opens critical findings by default and lists failing findings first' {
        $Html | Should -Match 'id="f-ad-007" class="finding sev-critical st-fail" open'
        $Html.IndexOf('id="f-ad-007"') | Should -BeLessThan $Html.IndexOf('id="f-ad-002"')
    }

    It 'truncates very long item lists' {
        InModuleScope IdentityGuard {
            $items = 1..250 | ForEach-Object { New-IGItem -Name "user$_" }
            $table = New-IGHtmlItemTable -Items $items
            $table | Should -Match '50 autre\(s\) objet\(s\)'
            ([regex]::Matches($table, '<tr><td>')).Count | Should -Be 200
        }
    }
}

Describe 'Security score' {
    It 'is 100 / A when every evaluated check passes and ignores checks that did not run' {
        InModuleScope IdentityGuard {
            $findings = @(
                (New-IGFinding -Id 'AD-002' -Severity 'Moyenne')
                (New-IGNotRunFinding -Id 'ENT-006' -Reason 'x')
            )
            $score = Get-IGSecurityScore -Finding $findings
            $score.Score | Should -Be 100
            $score.Grade | Should -Be 'A'
            $score.NotRun | Should -Be 1
        }
    }

    It 'is 0 / E when every evaluated check fails as Critique' {
        InModuleScope IdentityGuard {
            $item = New-IGItem -Name 'x'
            $findings = @(
                (New-IGFinding -Id 'AD-007' -Severity 'Critique' -Items @($item))
                (New-IGFinding -Id 'ENT-004' -Severity 'Critique' -Items @($item))
            )
            $score = Get-IGSecurityScore -Finding $findings
            $score.Score | Should -Be 0
            $score.Grade | Should -Be 'E'
        }
    }

    It 'weights failures by severity' {
        InModuleScope IdentityGuard {
            $item = New-IGItem -Name 'x'
            $findings = @(
                (New-IGFinding -Id 'AD-002' -Severity 'Moyenne' -Items @($item))
                (New-IGFinding -Id 'AD-003' -Severity 'Moyenne')
            )
            # Penalty 5 out of a worst case of 2 x 20 = 40 -> 87.5 -> 88.
            (Get-IGSecurityScore -Finding $findings).Score | Should -Be 88
        }
    }
}
