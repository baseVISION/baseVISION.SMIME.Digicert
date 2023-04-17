

# Run Account of Azure Automation Account only specify value when Shared Mailbox Support and PFX Export should be enabled in the script.
$RunAsObjectId = ""

# Managed Identity Object of VM
$VmMsiObjectId = ""

# Managed Identity of Automation Account
$AaMsiObjectId = ""

# Mailbox that will send mails with the exported PFX
$SendPFXMailbox

Install-Module -Name AzureAD -Scope AllUsers
Install-Module -Name ExchangeOnlineManagemenet -Scope AllUsers
Connect-AzureAD
Connect-ExchangeOnline

if($null -ne $RunAsObjectId){
    $exo = Get-AzureADServicePrincipal -Filter "AppID eq '00000002-0000-0ff1-ce00-000000000000'"

    # Use the Object Id as shown in the image above
    $msi = Get-AzureADServicePrincipal -ObjectId $AaMsiObjectId 

    $permission = $exo.AppRoles `
        | Where-Object { $_.Value -eq 'Exchange.ManageAsApp' } `
        | Select-Object -First 1

    New-AzureADServiceAppRoleAssignment `
        -Id $permission.Id `
        -ObjectId $msi.ObjectId `
        -PrincipalId $msi.ObjectId `
        -ResourceId $exo.ObjectId


    $roleName="Global Reader"
    $role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq $roleName}
    if ($null -eq $role) {
        $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object {$_.displayName -eq $roleName}
        Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
        $role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq $roleName}
    }
    Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $RunAsObjectId

    # Grant Mail.Send permission to VM identity

    $vmmsi = Get-AzureADServicePrincipal -ObjectId $VmMsiObjectId 

    $groupReadPermission = $graph.AppRoles `
        | Where-Object Value -Like "Mail.Send" `
        | Select-Object -First 1

    New-AzureADServiceAppRoleAssignment `
        -Id $groupReadPermission.Id `
        -ObjectId $vmmsi.ObjectId `
        -PrincipalId $vmmsi.ObjectId `
        -ResourceId $exo.ObjectId

    # Create mail-enabled security group to restrict send.mail permissions
    New-DistributionGroup `
        -Name "SMIME Send Mail Restriction" `
        -Description "Restrict Send.Mail permission to specified group members" `
        -Type security
    
    # Add member to distribution group, mails can only be sent through the defined member mailboxes
    Add-DistributionGroupMember `
        -Identity "SMIME Send Mail Restriction" `
        -Member $SendPFXMailbox
    
    # Create ApplicationAccessPolicy to effectively restrict access
    New-ApplicationAccessPolicy `
        -AppId $vmmsi.ObjectId `
        -PolicyScopeGroupId "SMIME Send Mail Restriction" `
        -AccessRight RestrictAccess
    
}