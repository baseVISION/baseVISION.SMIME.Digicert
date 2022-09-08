Install-Module -Name PowerShellGet -Repository PSGallery -Force
Install-Module -Name Microsoft.Graph.DeviceManagement.Administration -Scope AllUsers
Install-Module -Name Microsoft.Graph.Groups -Scope AllUsers
Install-Module -Name Microsoft.Graph.Users -Scope AllUsers
Install-Module -Name Microsoft.Graph.Users.Actions -Scope AllUsers
Install-Module -Name PSCertificateEnrollment -Scope AllUsers
Install-Module -Name WPNinjas.PasswordGeneration -Scope AllUsers
Install-Module -Name ExchangeOnlineManagement -Scope AllUsers

Copy-Item ".\IntunePfxImport\" "$($env:ProgramFiles)\WindowsPowerShell\Modules\" -Recurse -Container

Import-Module IntunePfxImport

Add-IntuneKspKey "Microsoft Software Key Storage Provider" "SMIME"
New-Item -Path "$($env:ProgramData)" -Name "baseVISION-SMIME" -ItemType Container -Force
Export-IntunePublicKey -ProviderName "Microsoft Software Key Storage Provider" -KeyName "SMIME" -FilePath "$($env:ProgramData)\baseVISION-SMIME\Intune-PublicKey.txt" 