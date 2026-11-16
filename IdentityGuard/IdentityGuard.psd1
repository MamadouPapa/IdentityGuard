@{
    RootModule           = 'IdentityGuard.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'a642e707-0592-4ada-ad2f-31fb9133bf75'
    Author               = 'Papa Mamadou Gueye'
    CompanyName          = 'Community'
    Copyright            = '(c) 2026 Papa Mamadou Gueye. MIT License.'
    Description          = 'Read-only identity security posture audit for Active Directory and Entra ID, producing a self-contained HTML report.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-IdentityGuard')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Security', 'Audit', 'ActiveDirectory', 'EntraID', 'MicrosoftGraph', 'Identity')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
