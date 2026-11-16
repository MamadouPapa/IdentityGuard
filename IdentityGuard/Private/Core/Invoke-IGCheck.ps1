function Invoke-IGCheck {
    <#
    .SYNOPSIS
        Runs one check in isolation: any failure becomes an Info "not run" finding instead of an exception.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Definition
    )

    # Promote non-terminating errors so they are caught below.
    $ErrorActionPreference = 'Stop'

    try {
        $finding = & $Definition.Function
        if ($null -eq $finding) {
            throw 'le contrôle n''a retourné aucun résultat.'
        }
        $finding
    }
    catch {
        $reason = $_.Exception.Message
        Write-Verbose ("[{0}] check not executed: {1}" -f $Definition.Id, $reason)
        New-IGNotRunFinding -Id $Definition.Id -Reason $reason
    }
}
