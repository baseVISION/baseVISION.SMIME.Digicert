<#
.DESCRIPTION
TThis script enables an administrator to delete a specific existing certificate from Intune.

.EXAMPLE


.NOTES
Author: Thomas Kurth/baseVISION
Date:   22.06.2022

History
    001: First Version

#>
$RunningInAzureVM = $true 
Select-MgProfile -Name "beta"

if($RunningInAzureVM){ 
    
    $response = Invoke-WebRequest -Uri ('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/') -Method GET -Headers @{Metadata="true"} -UseBasicParsing
    $content = $response.Content | ConvertFrom-Json
    # Azure AD
    $AADAuthBody = @{
        AccessToken   = $content.access_token
    }
} else {
    # Azure AD  - Empty will throw Interactive Auth
    $AADAuthBody = @{
        Scopes = @("User.Read.All","GroupMember.Read.All","DeviceManagementConfiguration.ReadWrite.All")
    }
}


try {
    $context = Get-MgContext -ErrorAction Stop
    if($null -eq $context){
        throw "Not connected"
    }
    
} catch {
    Connect-MgGraph @AADAuthBody 
}


$AllUserPFXs = ,(Get-MgDeviceManagementUserPfxCertificate -All -Property @("id","expirationDateTime","userPrincipalName"))
    
$PfxToDel = $AllUserPFXs  | Out-GridView -OutputMode Single 
Remove-MgDeviceManagementUserPfxCertificate -UserPfxCertificateId $PfxToDel.Id