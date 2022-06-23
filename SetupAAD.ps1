#Managed Identity Object of VM
$MsiObjectId = ""

if($MsiObjectId -eq ""){
    throw "MsiObjectId not set"
}

Install-Module -Name AzureAD -Scope AllUsers
Connect-AzureAD
$graph = Get-AzureADServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"


# Use the Object Id as shown in the image above
$msi = Get-AzureADServicePrincipal -ObjectId $MsiObjectId

$groupReadPermission = $graph.AppRoles `
    | where Value -Like "User.Read.All" `
    | Select-Object -First 1

New-AzureADServiceAppRoleAssignment `
    -Id $groupReadPermission.Id `
    -ObjectId $msi.ObjectId `
    -PrincipalId $msi.ObjectId `
    -ResourceId $graph.ObjectId



$groupReadPermission = $graph.AppRoles `
    | where Value -Like "GroupMember.Read.All" `
    | Select-Object -First 1

New-AzureADServiceAppRoleAssignment `
    -Id $groupReadPermission.Id `
    -ObjectId $msi.ObjectId `
    -PrincipalId $msi.ObjectId `
    -ResourceId $graph.ObjectId



$groupReadPermission = $graph.AppRoles `
    | where Value -Like "DeviceManagementConfiguration.ReadWrite.All" `
    | Select-Object -First 1

New-AzureADServiceAppRoleAssignment `
    -Id $groupReadPermission.Id `
    -ObjectId $msi.ObjectId `
    -PrincipalId $msi.ObjectId `
    -ResourceId $graph.ObjectId
