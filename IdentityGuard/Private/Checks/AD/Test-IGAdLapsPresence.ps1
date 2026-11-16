function Test-IGAdLapsPresence {
    <#
    .SYNOPSIS
        AD-010: legacy LAPS (ms-Mcs-AdmPwd) or Windows LAPS (msLAPS-Password) attribute in the schema.
    .NOTES
        Schema presence only: it does not prove every computer is covered by a LAPS policy.
    #>
    [CmdletBinding()]
    param()

    $attributes = @(Get-IGSource -Name 'ADLapsSchema')
    if ($attributes.Count -gt 0) {
        $note = 'Attribut(s) présent(s) dans le schéma : {0}. Vérifier la couverture effective (GPO / Intune).' -f ($attributes -join ', ')
        return New-IGFinding -Id 'AD-010' -Severity 'Élevée' -Count 0 -IsCompliant $true -Note $note
    }

    # Without LAPS, every enabled non-DC computer likely shares or reuses its local admin password.
    $computers = @(Get-IGNonDcComputer)
    $items = foreach ($computer in $computers) {
        New-IGItem -Name ([string]$computer.Name) -Detail ([string]$computer.OperatingSystem)
    }

    New-IGFinding -Id 'AD-010' -Severity 'Élevée' -Items $items -IsCompliant $false `
        -Note 'Aucun attribut ms-Mcs-AdmPwd ni msLAPS-Password dans le schéma : LAPS n''est pas déployé.'
}
