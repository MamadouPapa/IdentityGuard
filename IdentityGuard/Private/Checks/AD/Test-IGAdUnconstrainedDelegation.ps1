function Test-IGAdUnconstrainedDelegation {
    <#
    .SYNOPSIS
        AD-007: non-DC computers trusted for unconstrained delegation (TGT capture / coercion).
    #>
    [CmdletBinding()]
    param()

    $computers = @(Get-IGNonDcComputer | Where-Object { $_.TrustedForDelegation -eq $true })

    $items = foreach ($computer in $computers) {
        $os = if ($computer.OperatingSystem) { [string]$computer.OperatingSystem } else { 'Système inconnu' }
        New-IGItem -Name ([string]$computer.Name) -Detail ('{0} · TRUSTED_FOR_DELEGATION' -f $os)
    }

    New-IGFinding -Id 'AD-007' -Severity 'Critique' -Items $items
}
