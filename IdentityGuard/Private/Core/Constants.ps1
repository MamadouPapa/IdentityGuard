# Shared constants: severities, statuses, thresholds and well-known identifiers.

$script:IGSeverityOrder = @('Critique', 'Élevée', 'Moyenne', 'Faible', 'Info')

# Penalty weight of each failing finding (score is normalized, see Get-IGSecurityScore).
$script:IGSeverityWeight = @{
    'Critique' = 20
    'Élevée'   = 10
    'Moyenne'  = 5
    'Faible'   = 2
    'Info'     = 0
}

$script:IGStatus = @{
    Pass   = 'Conforme'
    Fail   = 'À corriger'
    NotRun = 'Non exécuté'
}

$script:IGThresholds = @{
    KrbtgtMaxAgeDays        = 180
    InactiveDays            = 90
    GuestStaleDays          = 90
    GuestPendingDays        = 30
    CredentialExpiryDays    = 30
    PrivilegedMembersHigh   = 10
    PrivilegedMembersMedium = 5
    GlobalAdminMax          = 4
    BreakGlassAllowance     = 2
}

# Score (0-100) lower bounds for each grade, evaluated in order.
$script:IGGradeScale = @(
    @{ Grade = 'A'; Min = 90 }
    @{ Grade = 'B'; Min = 75 }
    @{ Grade = 'C'; Min = 60 }
    @{ Grade = 'D'; Min = 40 }
    @{ Grade = 'E'; Min = 0 }
)

$script:IGReportMaxItems = 200

# primaryGroupID values of writable (516) and read-only (521) domain controllers.
$script:IGDomainControllerGroupIds = @(516, 521)

# Protected AD groups. 'Reported' groups feed AD-004; all feed the AdminCount orphan check.
$script:IGPrivilegedAdGroups = @(
    @{ Name = 'Domain Admins'; Rid = 512; ForestRoot = $false; Reported = $true }
    @{ Name = 'Enterprise Admins'; Rid = 519; ForestRoot = $true; Reported = $true }
    @{ Name = 'Schema Admins'; Rid = 518; ForestRoot = $true; Reported = $true }
    @{ Name = 'Administrators'; Sid = 'S-1-5-32-544'; Reported = $true }
    @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548'; Reported = $false }
    @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549'; Reported = $false }
    @{ Name = 'Print Operators'; Sid = 'S-1-5-32-550'; Reported = $false }
    @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; Reported = $false }
)

# Built-in Entra ID role template IDs considered privileged.
$script:IGPrivilegedEntraRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
}

$script:IGGlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

# Read-only Microsoft Graph scopes required by the Entra checks.
$script:IGGraphScopes = @(
    'User.Read.All'
    'AuditLog.Read.All'
    'Directory.Read.All'
    'Policy.Read.All'
    'UserAuthenticationMethod.Read.All'
    'RoleManagement.Read.Directory'
    'Application.Read.All'
)
