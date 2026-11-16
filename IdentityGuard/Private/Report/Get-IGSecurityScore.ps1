function Get-IGSecurityScore {
    <#
    .SYNOPSIS
        Computes a 0-100 score and a letter grade. Each failing finding costs its severity weight;
        the total is normalized against the worst case (every evaluated check failing as 'Critique').
        Checks that did not run are excluded and reported separately.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()] [object[]] $Finding = @()
    )

    $evaluated = @($Finding | Where-Object { $null -ne $_ -and $_.Status -ne $script:IGStatus.NotRun })
    $failing = @($evaluated | Where-Object { $_.Status -eq $script:IGStatus.Fail })
    $penalty = 0
    foreach ($item in $failing) {
        $penalty += [int]$script:IGSeverityWeight[[string]$item.Severity]
    }

    $worstCase = $evaluated.Count * [int]$script:IGSeverityWeight['Critique']
    $score = if ($worstCase -eq 0) { 100 } else { [math]::Round(100 - (100 * $penalty / $worstCase)) }
    $score = [math]::Max(0, [math]::Min(100, $score))
    $grade = ($script:IGGradeScale | Where-Object { $score -ge $_.Min } | Select-Object -First 1).Grade

    [pscustomobject]@{
        Score  = [int]$score
        Grade  = $grade
        Failed = $failing.Count
        Passed = @($Finding | Where-Object { $null -ne $_ -and $_.Status -eq $script:IGStatus.Pass }).Count
        NotRun = @($Finding | Where-Object { $null -ne $_ -and $_.Status -eq $script:IGStatus.NotRun }).Count
    }
}
