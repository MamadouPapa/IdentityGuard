function Invoke-IdentityGuard {
    <#
    .SYNOPSIS
        Runs the IdentityGuard read-only identity security audit and writes a self-contained HTML report.

    .DESCRIPTION
        Executes the Active Directory and/or Entra ID checks. Only Get-* cmdlets are used: nothing is
        modified in the directory. Each check is isolated: a missing module, permission or licence
        produces an "Info - Contrôle non exécuté" finding instead of stopping the audit.

        Entra checks require an existing Microsoft Graph session, for example:
        Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All','Policy.Read.All',
                                'UserAuthenticationMethod.Read.All','RoleManagement.Read.Directory','Application.Read.All'

    .PARAMETER Scope
        AD, Entra or All (default).

    .PARAMETER OutputPath
        HTML report file path, or an existing folder. Defaults to IdentityGuard-Report-<timestamp>.html
        in the current folder.

    .PARAMETER DemoMode
        Uses bundled synthetic data (no directory or tenant needed). Intended for demos and screenshots.

    .EXAMPLE
        Invoke-IdentityGuard -DemoMode -OutputPath .\docs\demo-report.html

    .EXAMPLE
        Connect-MgGraph -Scopes $scopes; Invoke-IdentityGuard -Scope All -OutputPath C:\Audit\

    .OUTPUTS
        PSCustomObject with ReportPath, Score, Grade and Findings (uniform finding objects).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('AD', 'Entra', 'All')]
        [string] $Scope = 'All',

        [string] $OutputPath,

        [switch] $DemoMode
    )

    $script:IGDemoMode = $DemoMode.IsPresent
    $script:IGSourceCache = @{}

    $definitions = @(Get-IGCheckDefinition -Scope $Scope)
    $findings = New-Object System.Collections.Generic.List[object]

    for ($index = 0; $index -lt $definitions.Count; $index++) {
        $definition = $definitions[$index]
        $percent = [int](($index / $definitions.Count) * 100)
        Write-Progress -Activity 'IdentityGuard' -Status ('{0} – {1}' -f $definition.Id, $definition.Title) -PercentComplete $percent
        $findings.Add((Invoke-IGCheck -Definition $definition))
    }
    Write-Progress -Activity 'IdentityGuard' -Completed

    $reportPath = Resolve-IGOutputPath -OutputPath $OutputPath
    $context = Get-IGReportContext -Scope $Scope -IsDemo:$DemoMode
    $html = ConvertTo-IGHtmlReport -Finding $findings.ToArray() -Context $context
    [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding($false)))
    Write-Verbose "IdentityGuard report written to $reportPath"

    $score = Get-IGSecurityScore -Finding $findings.ToArray()
    [pscustomobject]@{
        PSTypeName = 'IdentityGuard.Result'
        ReportPath = $reportPath
        Score      = $score.Score
        Grade      = $score.Grade
        Failed     = $score.Failed
        Passed     = $score.Passed
        NotRun     = $score.NotRun
        Findings   = $findings.ToArray()
    }
}
