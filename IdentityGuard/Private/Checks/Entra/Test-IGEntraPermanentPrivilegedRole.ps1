function Get-IGEntraPrincipalNameMap {
    <#
    .SYNOPSIS
        Maps object id -> UPN when the user list is readable; principals that are not users keep their id.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $map = @{}
    $users = Get-IGOptionalSource -Name 'EntraUsers'
    foreach ($user in @($users | Where-Object { $null -ne $_ })) {
        $map[[string]$user.Id] = Get-IGEntraUserName -User $user
    }
    $map
}

function Test-IGEntraPermanentPrivilegedRole {
    <#
    .SYNOPSIS
        ENT-002: active, non-expiring (permanent) assignments of privileged directory roles.
    #>
    [CmdletBinding()]
    param()

    $permanent = @(Get-IGSource -Name 'EntraRoleAssignments' | Where-Object {
            $script:IGPrivilegedEntraRoles.ContainsKey([string]$_.RoleDefinitionId) -and
            $_.AssignmentType -ne 'Activated' -and
            $null -eq (ConvertTo-IGDateTime -Value $_.EndDateTime)
        })

    $names = Get-IGEntraPrincipalNameMap
    $items = foreach ($assignment in $permanent) {
        $principal = if ($names.ContainsKey($assignment.PrincipalId)) { $names[$assignment.PrincipalId] } else { $assignment.PrincipalId }
        New-IGItem -Name $principal -Detail ('{0} · permanent' -f $script:IGPrivilegedEntraRoles[$assignment.RoleDefinitionId])
    }

    $globalAdmins = @($permanent | Where-Object { $_.RoleDefinitionId -eq $script:IGGlobalAdminRoleId }).Count
    $severity = if ($globalAdmins -gt $script:IGThresholds.GlobalAdminMax) { 'Élevée' } else { 'Moyenne' }
    $sources = @($permanent | ForEach-Object { $_.Source } | Sort-Object -Unique) -join ', '
    $note = 'Global Administrator permanents : {0} (recommandé : moins de 5, dont 2 comptes d''urgence). Source : {1}.' -f $globalAdmins, $(if ($sources) { $sources } else { 'n/a' })

    New-IGFinding -Id 'ENT-002' -Severity $severity -Items $items `
        -IsCompliant ($permanent.Count -le $script:IGThresholds.BreakGlassAllowance) -Note $note
}
