function Get-IGPrivilegedMemberSeverity {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [int] $Count
    )

    if ($Count -gt $script:IGThresholds.PrivilegedMembersHigh) { return 'Élevée' }
    if ($Count -gt $script:IGThresholds.PrivilegedMembersMedium) { return 'Moyenne' }
    'Faible'
}

function Test-IGAdPrivilegedGroupMember {
    <#
    .SYNOPSIS
        AD-004: unique (recursive) members of Domain/Enterprise/Schema Admins and Administrators.
    #>
    [CmdletBinding()]
    param()

    $memberships = @(Get-IGSource -Name 'ADPrivilegedMembers' | Where-Object { $_.IsReported -eq $true })
    $byMember = @($memberships | Group-Object -Property SamAccountName | Sort-Object -Property Name)

    $items = foreach ($member in $byMember) {
        $groups = @($member.Group | ForEach-Object { $_.Group } | Sort-Object -Unique)
        New-IGItem -Name $member.Name -Detail ('Membre de : {0}' -f ($groups -join ', '))
    }

    $count = $byMember.Count
    $limit = $script:IGThresholds.PrivilegedMembersMedium
    $note = '{0} compte(s) à privilèges distinct(s). Objectif : {1} au maximum, revue trimestrielle.' -f $count, $limit

    New-IGFinding -Id 'AD-004' -Severity (Get-IGPrivilegedMemberSeverity -Count $count) -Items $items `
        -IsCompliant ($count -le $limit) -Note $note
}
