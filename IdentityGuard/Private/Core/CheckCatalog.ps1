# Catalog of checks: metadata (French, report-facing) and the function implementing each check.

$script:IGAnssiAdGuide = 'ANSSI (CERT-FR) – Points de contrôle Active Directory : https://www.cert.ssi.gouv.fr/uploads/guide-ad.html'

$script:IGCheckCatalog = @(
    [pscustomobject]@{
        Id          = 'AD-001'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Mot de passe du compte krbtgt non renouvelé depuis plus de 180 jours'
        Function    = 'Test-IGAdKrbtgtPasswordAge'
        Remediation = 'Réinitialiser le mot de passe krbtgt deux fois, en attendant entre les deux la réplication complète et la durée de vie maximale des tickets (10 h par défaut). Utiliser le script officiel New-KrbtgtKeys.ps1 et planifier une rotation au moins tous les 180 jours.'
        Reference   = "MITRE ATT&CK T1558.001 (Golden Ticket) ; $script:IGAnssiAdGuide ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password"
    }
    [pscustomobject]@{
        Id          = 'AD-002'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Comptes actifs dont le mot de passe n''expire jamais'
        Function    = 'Test-IGAdPasswordNeverExpires'
        Remediation = 'Retirer l''option PasswordNeverExpires des comptes utilisateurs. Migrer les comptes de service vers des gMSA (rotation automatique) ou appliquer une stratégie de mot de passe affinée (FGPP) avec des secrets longs.'
        Reference   = "MITRE ATT&CK T1078.002, T1110 ; $script:IGAnssiAdGuide"
    }
    [pscustomobject]@{
        Id          = 'AD-003'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Comptes actifs inactifs depuis plus de 90 jours'
        Function    = 'Test-IGAdInactiveAccount'
        Remediation = 'Désactiver puis supprimer après validation les comptes inactifs (processus arrivées/départs). Note : lastLogonTimestamp est répliqué avec un décalage pouvant atteindre 14 jours.'
        Reference   = "MITRE ATT&CK T1078.002 ; $script:IGAnssiAdGuide"
    }
    [pscustomobject]@{
        Id          = 'AD-004'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Membres des groupes à privilèges (Domain Admins, Enterprise Admins, Schema Admins, Administrators)'
        Function    = 'Test-IGAdPrivilegedGroupMember'
        Remediation = 'Réduire au strict minimum les membres des groupes à privilèges, utiliser des comptes d''administration dédiés (modèle en tiers), vider Schema Admins et Enterprise Admins hors opérations ponctuelles et placer les comptes dans Protected Users.'
        Reference   = "MITRE ATT&CK T1078.002, T1069.002 ; $script:IGAnssiAdGuide ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models"
    }
    [pscustomobject]@{
        Id          = 'AD-005'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Comptes sans pré-authentification Kerberos (AS-REP roasting)'
        Function    = 'Test-IGAdAsRepRoastable'
        Remediation = 'Désactiver l''option « Ne pas demander la pré-authentification Kerberos » (DONT_REQ_PREAUTH) sur tous les comptes, puis renouveler leur mot de passe.'
        Reference   = "MITRE ATT&CK T1558.004 (AS-REP Roasting) ; $script:IGAnssiAdGuide"
    }
    [pscustomobject]@{
        Id          = 'AD-006'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Comptes utilisateurs avec SPN (Kerberoasting)'
        Function    = 'Test-IGAdKerberoastable'
        Remediation = 'Remplacer les comptes de service par des gMSA, sinon imposer des mots de passe aléatoires de plus de 25 caractères, le chiffrement AES uniquement, et retirer tout privilège d''administration à ces comptes.'
        Reference   = "MITRE ATT&CK T1558.003 (Kerberoasting) ; $script:IGAnssiAdGuide"
    }
    [pscustomobject]@{
        Id          = 'AD-007'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Délégation Kerberos non contrainte sur des ordinateurs hors contrôleurs de domaine'
        Function    = 'Test-IGAdUnconstrainedDelegation'
        Remediation = 'Remplacer la délégation non contrainte par une délégation contrainte ou basée sur les ressources (RBCD). Marquer les comptes à privilèges « Le compte est sensible et ne peut pas être délégué ».'
        Reference   = "MITRE ATT&CK T1558, T1187 ; $script:IGAnssiAdGuide ; https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
    }
    [pscustomobject]@{
        Id          = 'AD-008'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Comptes AdminCount=1 orphelins (hors groupes protégés)'
        Function    = 'Test-IGAdAdminCountOrphan'
        Remediation = 'Vérifier que le compte n''a plus de rôle privilégié, remettre adminCount à 0 et réactiver l''héritage des permissions (ACL figées par AdminSDHolder).'
        Reference   = "MITRE ATT&CK T1078.002 ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
    }
    [pscustomobject]@{
        Id          = 'AD-009'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Comptes actifs autorisés à avoir un mot de passe vide (PASSWD_NOTREQD)'
        Function    = 'Test-IGAdPasswordNotRequired'
        Remediation = 'Retirer le drapeau PASSWD_NOTREQD (Set-ADUser -PasswordNotRequired $false) puis forcer la définition d''un mot de passe conforme.'
        Reference   = "MITRE ATT&CK T1078.002, T1110.001 ; $script:IGAnssiAdGuide"
    }
    [pscustomobject]@{
        Id          = 'AD-010'
        Scope       = 'AD'
        Category    = 'Active Directory'
        Title       = 'Solution LAPS absente du schéma Active Directory'
        Function    = 'Test-IGAdLapsPresence'
        Remediation = 'Déployer Windows LAPS (intégré à Windows depuis avril 2023) pour rendre uniques et renouveler automatiquement les mots de passe administrateur local.'
        Reference   = "MITRE ATT&CK T1078.003, T1550.002 ; $script:IGAnssiAdGuide ; https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
    }
    [pscustomobject]@{
        Id          = 'ENT-001'
        Scope       = 'Entra'
        Category    = 'Entra ID'
        Title       = 'Comptes membres sans méthode MFA enregistrée'
        Function    = 'Test-IGEntraMfaRegistration'
        Remediation = 'Imposer l''enregistrement MFA (campagne d''enregistrement, Accès conditionnel), en priorité pour les administrateurs, et privilégier les méthodes résistantes au phishing (FIDO2, Windows Hello, passkeys).'
        Reference   = 'MITRE ATT&CK T1078.004, T1110.003 ; https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity'
    }
    [pscustomobject]@{
        Id          = 'ENT-002'
        Scope       = 'Entra'
        Category    = 'Entra ID'
        Title       = 'Attributions permanentes de rôles à privilèges Entra ID'
        Function    = 'Test-IGEntraPermanentPrivilegedRole'
        Remediation = 'Convertir les attributions permanentes en attributions éligibles via Privileged Identity Management (PIM), limiter les Global Administrator à moins de 5 et ne conserver que 2 comptes d''urgence (break-glass) permanents.'
        Reference   = 'MITRE ATT&CK T1078.004, T1098.003 ; https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
    }
    [pscustomobject]@{
        Id          = 'ENT-003'
        Scope       = 'Entra'
        Category    = 'Entra ID'
        Title       = 'Comptes invités obsolètes'
        Function    = 'Test-IGEntraStaleGuest'
        Remediation = 'Mettre en place des revues d''accès périodiques sur les invités, supprimer les invitations non acceptées et les invités sans connexion récente.'
        Reference   = 'MITRE ATT&CK T1078.004 ; https://learn.microsoft.com/en-us/entra/id-governance/manage-guest-access-with-access-reviews'
    }
    [pscustomobject]@{
        Id          = 'ENT-004'
        Scope       = 'Entra'
        Category    = 'Entra ID'
        Title       = 'Paramètres de sécurité par défaut / stratégies d''Accès conditionnel'
        Function    = 'Test-IGEntraConditionalAccess'
        Remediation = 'Activer les paramètres de sécurité par défaut ou, avec Entra ID P1, déployer des stratégies d''Accès conditionnel (MFA pour tous, blocage de l''authentification héritée, MFA renforcée pour les administrateurs).'
        Reference   = 'MITRE ATT&CK T1078.004, T1110 ; https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults'
    }
    [pscustomobject]@{
        Id          = 'ENT-005'
        Scope       = 'Entra'
        Category    = 'Entra ID'
        Title       = 'Secrets et certificats d''applications expirés ou expirant sous 30 jours'
        Function    = 'Test-IGEntraAppCredentialExpiry'
        Remediation = 'Renouveler les secrets/certificats avant expiration, supprimer les identifiants expirés et préférer les certificats ou les identités managées aux secrets clients.'
        Reference   = 'MITRE ATT&CK T1098.001 ; https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials'
    }
    [pscustomobject]@{
        Id          = 'ENT-006'
        Scope       = 'Entra'
        Category    = 'Entra ID'
        Title       = 'Comptes membres actifs sans connexion depuis plus de 90 jours'
        Function    = 'Test-IGEntraStaleAccount'
        Remediation = 'Désactiver puis supprimer les comptes inactifs après validation métier. Nécessite Entra ID P1 pour la propriété signInActivity.'
        Reference   = 'MITRE ATT&CK T1078.004 ; https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts'
    }
)
