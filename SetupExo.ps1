

# Run Account of Azure Automation Account only specify value when Shared Mailbox Support should be enabled in the script.
$RunAsObjectId = ""

Install-Module -Name AzureAD -Scope AllUsers
Connect-AzureAD

if($null -ne $RunAsObjectId){
    $exo = Get-AzureADServicePrincipal -Filter "AppID eq '00000002-0000-0ff1-ce00-000000000000'"

    # Use the Object Id as shown in the image above
    $msi = Get-AzureADServicePrincipal -ObjectId $RunAsObjectId 

    $permission = $exo.AppRoles `
        | Where-Object { $_.Value -eq 'Exchange.ManageAsApp' } `
        | Select-Object -First 1

    New-AzureADServiceAppRoleAssignment `
        -Id $permission.Id `
        -ObjectId $msi.ObjectId `
        -PrincipalId $msi.ObjectId `
        -ResourceId $exo.ObjectId


    $roleName="Global Reader"
    $role = Get-AzureADDirectoryRole | Where {$_.displayName -eq $roleName}
    if ($role -eq $null) {
        $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where {$_.displayName -eq $roleName}
        Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
        $role = Get-AzureADDirectoryRole | Where {$_.displayName -eq $roleName}
    }
    Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $RunAsObjectId
}