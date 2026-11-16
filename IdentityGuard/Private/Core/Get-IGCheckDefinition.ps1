function Get-IGCheckDefinition {
    <#
    .SYNOPSIS
        Returns check definitions from the catalog, filtered by scope or by Id.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Scope')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Scope')]
        [ValidateSet('AD', 'Entra', 'All')]
        [string] $Scope = 'All',

        [Parameter(Mandatory, ParameterSetName = 'Id')]
        [string] $Id
    )

    if ($PSCmdlet.ParameterSetName -eq 'Id') {
        $definition = $script:IGCheckCatalog | Where-Object { $_.Id -eq $Id }
        if ($null -eq $definition) {
            throw "Unknown check id '$Id'."
        }
        return $definition
    }

    $script:IGCheckCatalog | Where-Object { $Scope -eq 'All' -or $_.Scope -eq $Scope }
}
