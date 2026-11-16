function Test-IGEntraMfaRegistration {
    <#
    .SYNOPSIS
        ENT-001: member users not registered for MFA (userRegistrationDetails report).
    #>
    [CmdletBinding()]
    param()

    $members = @(Get-IGSource -Name 'EntraRegistration' | Where-Object { -not (Test-IGEntraIsGuest -User $_) })
    $unregistered = @($members | Where-Object { $_.IsMfaRegistered -ne $true })

    $items = foreach ($user in $unregistered) {
        $role = if ($user.IsAdmin -eq $true) { 'Administrateur' } else { 'Utilisateur' }
        New-IGItem -Name (Get-IGEntraUserName -User $user) -Detail ('{0} · aucune méthode MFA enregistrée' -f $role)
    }

    $hasAdmin = @($unregistered | Where-Object { $_.IsAdmin -eq $true }).Count -gt 0
    $severity = if ($hasAdmin) { 'Critique' } else { 'Élevée' }
    $note = '{0} compte(s) membre(s) sur {1} sans MFA enregistrée.' -f $unregistered.Count, $members.Count

    New-IGFinding -Id 'ENT-001' -Severity $severity -Items $items -Note $note
}
