<#
.DESCRIPTION
This script is able to automatically retrieve SMIME/Client Auth certificates from digicert and upload them to Intune. Including renewing the existing certificates when required.

The Managed Identity of the VM requires:
 - MSGraph
   - User.Read.All
   - GroupMember.Read.All
   - DeviceManagementConfiguration.ReadWrite.All

The following needs to be assigned to the Run Account of tha Azure Automation account if SharedMailbox Support should be enabled.
- Office 365 Exchange Online
   - Exchange.ManageAsApp

Additionally, the service principal needs to get the the "Exchange Administrator" role assigned in Azure AD to read the shared mailbox permissions.
   

Setup
 - Setup an Azure Automation Account
 - Setup a Hybrid Worker and Install the Intune Certificate connector
 - Build Powershell Module according to https://github.com/microsoft/Intune-Resource-Access/tree/master/src/PFXImportPowershell

Possible Errors
# bad_request_format - Could not parse request data --> This could be because, that no credit card was saved withtin the Digicert Account.
#

.EXAMPLE


.NOTES
Author: Thomas Kurth/baseVISION
Date:   11.06.2022

History
    001: First Version

ExitCodes:
    99001: Could not Write to LogFile
    99002: Could not Write to Windows Log
    99003: Could not Set ExitMessageRegistry
#>

[CmdletBinding()]
Param()

## Manual Variable Definition
########################################################

$DebugPreference = "Continue"
$ScriptVersion = "001"
$ScriptName = "CertificateRequestor-Digicert"


$LogFilePathFolder = "$($env:ProgramData)\baseVISION-SMIME\Logs"
$FallbackScriptPath = "C:\Windows" # This is only used if the filename could not be resolved(IE running in ISE)

# Log Configuration
$DefaultLogOutputMode = "Console-LogFile" # "Console-LogFile","Console-WindowsEvent","LogFile-WindowsEvent","Console","LogFile","WindowsEvent","All"
$DefaultLogWindowsEventSource = $ScriptName
$DefaultLogWindowsEventLog = "CustomPS"

# Digicert Configuration
$baseUrl = "https://www.digicert.com/services/v2"
$ApiKey = Get-AutomationVariable -Name 'DigiCertApiKey'
$DigicertOrgId = Get-AutomationVariable -Name 'DigiCertOrgId'
$CertificateProduct = Get-AutomationVariable -Name 'DigiCertProduct' 
<# Choose from the following list of types
client_premium - Premium
client_digital_signature_plus - Digital Signature Plus
client_authentication_plus - Authentication Plus
client_email_security_plus - Email Security Plus
class1_smime - Class 1 S/Mime Certificate
Source: https://dev.digicert.com/services-api/orders/order-client-certificate/
#>

$ScopeGroupId = Get-AutomationVariable -Name 'AADScopeGroupId'
$EnablePFXExport = Get-AutomationVariable -Name 'EnablePFXExport'
$PFXExportPasswordMailbox = Get-AutomationVariable -Name 'PFXExportPasswordMailbox'

# Azure VM with Managed Identity
$RunningInAzureVM = $true
$EnableSharedMailboxSupport = Get-AutomationVariable -Name 'EnableSharedMailboxSupport' 
$TenantName = Get-AutomationVariable -Name 'TenantName' 
 
#region Functions
########################################################

function Write-Log {
    <#
    .DESCRIPTION
    Write text to a logfile with the current time.

    .PARAMETER Message
    Specifies the message to log.

    .PARAMETER Type
    Type of Message ("Info","Debug","Warn","Error").

    .PARAMETER OutputMode
    Specifies where the log should be written. Possible values are "Console","LogFile" and "Both".

    .PARAMETER Exception
    You can write an exception object to the log file if there was an exception.

    .EXAMPLE
    Write-Log -Message "Start process XY"

    .NOTES
    This function should be used to log information to console or log file.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [String]
        $Message
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Debug", "Warn", "Error")]
        [String]
        $Type = "Debug"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Console-LogFile", "Console-WindowsEvent", "LogFile-WindowsEvent", "Console", "LogFile", "WindowsEvent", "All")]
        [String]
        $OutputMode = $DefaultLogOutputMode
        ,
        [Parameter(Mandatory = $false)]
        [Exception]
        $Exception
    )
    
    $DateTimeString = Get-Date -Format "yyyy-MM-dd HH:mm:sszz"
    $Output = ($DateTimeString + "`t" + $Type.ToUpper() + "`t" + $Message)
    if ($Exception) {
        $ExceptionString = ("[" + $Exception.GetType().FullName + "] " + $Exception.Message)
        $Output = "$Output - $ExceptionString"
    }

    if ($OutputMode -eq "Console" -OR $OutputMode -eq "Console-LogFile" -OR $OutputMode -eq "Console-WindowsEvent" -OR $OutputMode -eq "All") {
        if ($Type -eq "Error") {
            Write-Error $output
        }
        elseif ($Type -eq "Warn") {
            Write-Warning $output
        }
        elseif ($Type -eq "Debug") {
            Write-Debug $output
        }
        else {
            Write-Verbose $output -Verbose
        }
    }
    
    if ($OutputMode -eq "LogFile" -OR $OutputMode -eq "Console-LogFile" -OR $OutputMode -eq "LogFile-WindowsEvent" -OR $OutputMode -eq "All") {
        try {
            Add-Content $LogFilePath -Value $Output -ErrorAction Stop
        }
        catch {
            exit 99001
        }
    }

    if ($OutputMode -eq "Console-WindowsEvent" -OR $OutputMode -eq "WindowsEvent" -OR $OutputMode -eq "LogFile-WindowsEvent" -OR $OutputMode -eq "All") {
        try {
            New-EventLog -LogName $DefaultLogWindowsEventLog -Source $DefaultLogWindowsEventSource -ErrorAction SilentlyContinue
            switch ($Type) {
                "Warn" {
                    $EventType = "Warning"
                    break
                }
                "Error" {
                    $EventType = "Error"
                    break
                }
                default {
                    $EventType = "Information"
                }
            }
            Write-EventLog -LogName $DefaultLogWindowsEventLog -Source $DefaultLogWindowsEventSource -EntryType $EventType -EventId 1 -Message $Output -ErrorAction Stop
        }
        catch {
            exit 99002
        }
    }
}

function New-Folder {
    <#
    .DESCRIPTION
    Creates a Folder if it's not existing.

    .PARAMETER Path
    Specifies the path of the new folder.

    .EXAMPLE
    CreateFolder "c:\temp"

    .NOTES
    This function creates a folder if doesn't exist.
    #>
    param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$Path
    )
    # Check if the folder Exists

    if (Test-Path $Path) {
        Write-Log "Folder: $Path Already Exists"
    }
    else {
        New-Item -Path $Path -type directory | Out-Null
        Write-Log "Creating $Path"
    }
}

function Set-RegValue {
    <#
    .DESCRIPTION
    Set registry value and create parent key if it is not existing.

    .PARAMETER Path
    Registry Path

    .PARAMETER Name
    Name of the Value

    .PARAMETER Value
    Value to set

    .PARAMETER Type
    Type = Binary, DWord, ExpandString, MultiString, String or QWord

    #>
    param(
        [Parameter(Mandatory = $True)]
        [string]$Path,
        [Parameter(Mandatory = $True)]
        [string]$Name,
        [Parameter(Mandatory = $True)]
        [AllowEmptyString()]
        [string]$Value,
        [Parameter(Mandatory = $True)]
        [string]$Type
    )
    
    try {
        $ErrorActionPreference = 'Stop' # convert all errors to terminating errors
        Start-Transaction

        if (Test-Path $Path -erroraction silentlycontinue) {      
 
        }
        else {
            New-Item -Path $Path -Force
            Write-Log "Registry key $Path created"  
        } 
        $null = New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force
        Write-Log "Registry Value $Path, $Name, $Type, $Value set"
        Complete-Transaction
    }
    catch {
        Undo-Transaction
        Write-Log "Registry value not set $Path, $Name, $Value, $Type" -Type Error -Exception $_.Exception
    }
}

function Remove-LineCarriage {
    param($object)

	$result = [System.String] $object;
	$result = $result -replace "`t","";
	$result = $result -replace "`n","";
	$result = $result -replace "`r","";
	$result = $result -replace " ;",";";
	$result = $result -replace "; ",";";
	$result = $result -replace [Environment]::NewLine, "";
	
	return $result;
}

function New-DigicertSmimeOrder {
    param(
        [Guid]$UserId,
        [string]$PrimaryMail,
        [String[]]$MailAliases,
        [String]$DisplayName
    )
    $MailAliases = @($PrimaryMail) + $MailAliases
    $MailAliases = $MailAliases | Select-Object -Unique
    # Edge Case where empty ProxyAddresses remain in the array
    $MailAliases = $MailAliases | Where-Object {$_ -ne ""}
    # Create New CSR
    $csr = New-CertificateRequest -Email $MailAliases -PrivateKeyExportable -ValidityPeriod Years -ValidityPeriodUnits 1 -KeyLength 2048 -MachineContext
    # TODO perhaps add -Subject "CN=$DisplayName"
    $DisplayName = Convert-Umlaut -Text $DisplayName
    # Order Certificate
    $ReqData = @{
        "certificate" = @{
            "common_name" = $DisplayName
            "emails" = $MailAliases
            "signature_hash" = "sha256"
            "csr" = (Remove-LineCarriage -object $csr)
        }
        "skip_approval" = $true
        "organization" = @{
            "id" = $DigicertOrgId
        }
        "order_validity" = @{
            "years" = 1
        }
        "payment_method" = "profile"
    }

    Write-Log -Message "DigicertOrder Body: '$($ReqData | ConvertTo-Json)'" -Type Debug
      
    $Request = @{
        Uri = "$baseUrl/order/certificate/$CertificateProduct"
        Method = "POST"
        ContentType = "application/json"
        Headers = @{"X-DC-DEVKEY"="$ApiKey"}
        Body = ($ReqData | ConvertTo-Json)
    }
    $Order = Invoke-WebRequest @Request -UseBasicParsing
    Write-Log -Message "DigicertOrder Result: '$($Order | Format-List)'" -Type Debug
    if($Order.StatusCode -ne 201){
        Write-Log -Message "DigicertOrder failed with result '$($Order.Content)'" -Type Error
        throw "Failed to create request: $($Order.Content)"
    }
    Write-Log -Message "Save order info to '$($env:ProgramData)\baseVISION-SMIME\Orders\$UserId.json'" -Type Debug
    $Order.Content | Out-File -FilePath "$($env:ProgramData)\baseVISION-SMIME\Orders\$UserId.json" -Force

}
function Invoke-DigicertSmimeInstall {
    param(
        [Int32]$OrderId
    )
    $Request = @{
        Uri = "$baseUrl/certificate/download/order/$OrderId/format/p7b"
        Method = "GET"
        ContentType = "application/x-pkcs7-certificates"
        Headers = @{"X-DC-DEVKEY"="$ApiKey"}
    }
    $CerResult = Invoke-WebRequest @Request -UseBasicParsing
    Write-Log -Message "Digicert Certificate Result: '$($CerResult.Content)'" -Type Debug
    if($CerResult.StatusCode -ne 200){
        Write-Log -Message "Get Digicert certificate failed with result '$($CerResult.Content)'" -Type Error
        throw "Failed to get certificate: $($CerResult.Content)"
    }
    
    $ExecutionDate = Get-Date -Format "yyyyMMddHHmm"
    [System.Text.Encoding]::ASCII.GetString($CerResult.Content) | Out-File -FilePath "$($env:ProgramData)\baseVISION-SMIME\Orders\Issued\$($ExecutionDate)-$($User.Id).p7b"
    $cert = Import-Certificate -FilePath "$($env:ProgramData)\baseVISION-SMIME\Orders\Issued\$($ExecutionDate)-$($User.Id).p7b" -CertStoreLocation cert:\LocalMachine\My

    Write-Log -Message "Installed Certificate of Order Id '$OrderId' with thumbprint '$($cert.Thumbprint)'" -Type Info
    Move-Item -Path "$($env:ProgramData)\baseVISION-SMIME\Orders\$($User.Id).json" -Destination "$($env:ProgramData)\baseVISION-SMIME\Orders\Issued\$($ExecutionDate)-$($User.Id).json" -Force
                
    return $cert | Where-Object { $_.HasPrivateKey -eq $true }
}
function Get-DigicertSmimeOrder {
    param(
        [Int32]$OrderId
    )
      
    $Request = @{
        Uri = "$baseUrl/order/certificate/$OrderId"
        Method = "GET"
        ContentType = "application/json"
        Headers = @{"X-DC-DEVKEY"="$ApiKey"}
    }
    $OrderResult = Invoke-WebRequest @Request -UseBasicParsing
    Write-Log -Message "DigicertOrder Result: '$($OrderResult.Content)'" -Type Debug
    if($OrderResult.StatusCode -ne 200){
        Write-Log -Message "Get DigicertOrder failed with result '$($OrderResult.Content)'" -Type Error
        throw "Failed to get order status: $($OrderResult.Content)"
    }
    $Result = $OrderResult.Content | ConvertFrom-Json

    Write-Log -Message "Order Id '$OrderId' for '$($Result.certificate.common_name)' with status '$($Result.status)' found." -Type Debug
    return $Result.status

}

function Upload-PfxToIntune {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
        [String]$Upn
    )


    $Password = Invoke-SecurePasswordGeneration
    Write-Log -Message "Export certificate as temp pfx for upload." -Type Debug
    Export-PfxCertificate -Cert $Certificate -Password $Password -FilePath "$($env:ProgramData)\baseVISION-SMIME\temp\cert.pfx"

    # Using existin Intune module to create encrypted blog instead of creating a new library.
    $UserPfx = New-IntuneUserPfxCertificate -PathToPfxFile "$($env:ProgramData)\baseVISION-SMIME\temp\cert.pfx" -PfxPassword  $Password -ProviderName "Microsoft Software Key Storage Provider" -KeyName "SMIME" -IntendedPurpose SmimeSigning -UPN $Upn

    # creating hashtable as an object is not working
    $UserPfxBody = @{
        CreatedDateTime = $UserPfx.CreatedDateTime 
        EncryptedPfxBlob  = $UserPfx.EncryptedPfxBlob
        EncryptedPfxPassword = $UserPfx.EncryptedPfxPassword
        ExpirationDateTime = $UserPfx.ExpirationDateTime.DateTime
        IntendedPurpose = $UserPfx.IntendedPurpose
        KeyName = $UserPfx.KeyName
        LastModifiedDateTime = $UserPfx.LastModifiedDateTime.DateTime
        PaddingScheme = $UserPfx.PaddingScheme
        ProviderName = $UserPfx.ProviderName
        StartDateTime = $UserPfx.StartDateTime.DateTime
        Thumbprint = $UserPfx.Thumbprint
        UserPrincipalName = $UserPfx.UserPrincipalName
    }
    Write-Log -Message "Start uploading cert to Intune" -Type Debug
    New-MgDeviceManagementUserPfxCertificate -BodyParameter $UserPfxBody
    Write-Log -Message "Delete temp pfx cert" -Type Debug
    Remove-Item -Path "$($env:ProgramData)\baseVISION-SMIME\temp\cert.pfx" -Force
}
function Convert-Umlaut
{
  param
  (
    [Parameter(Mandatory)]
    $Text
  )
    
  $output = $Text.Replace('ö','oe').Replace('ä','ae').Replace('ü','ue').Replace('ß','ss').Replace('Ö','Oe').Replace('Ü','Ue').Replace('Ä','Ae')
  $isCapitalLetter = $Text -ceq $Text.toUpper()
  if ($isCapitalLetter) 
  { 
    $output = $output.toUpper() 
  }
  $output
}

function Send-PFXCertificate {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
        $User
    )

    # Create a password and export the PFX certificate
	Add-Type -AssemblyName System.Web
	$ExportPass = [System.Web.Security.Membership]::GeneratePassword(24,2)
	$EncryptedExportPass = ConvertTo-SecureString -String $ExportPass -AsPlainText -Force
    Write-Log -Message "Export certificate as temp pfx to send to employee." -Type Debug
    Export-PfxCertificate -Cert $Certificate -Password $EncryptedExportPass -FilePath "$($env:ProgramData)\baseVISION-SMIME\temp\export-cert.pfx"

    # Convert PFX to make it sendable as attachment
    $PfxBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$($env:ProgramData)\baseVISION-SMIME\temp\export-cert.pfx"))
	Write-Log -Message "Certificate converted for attachment." -Type Debug

    # Send the PFX to the user
    $EmployeeEmailRecipient = @{
		EmailAddress = @{
			address = $User.AdditionalProperties.userPrincipalName
		}
	}
    $EmployeeHtmlHeader = "<h2>Your S/MIME certificate</h2>"
    $EmployeeHtmlBody = "<p>Please find the PFX of your S/MIME certificate attached with this mail.</p>
                 <p>To import the PFX to your non-managed device, please contact $PFXExportPasswordMailbox so they can share the export password with you."
    $EmployeeHtmlMsg = $EmployeeHtmlHeader + $EmployeeHtmlBody

    $EmployeeMessageBody = @{
        content = "$($EmployeeHtmlMsg)";
        ContentType = "html"
    }

    $EmployeePfxAttachment = @{
        "@odata.type" = "#microsoft.graph.fileAttachment";
        name = "SMIME PFX Certificate.pfx";
        contentBytes = $PfxBase64
    }

    $EmployeeMessage = @{
        subject = "Your S/MIME certificate";
        toRecipients = @($EmployeeEmailRecipient);
        body = $EmployeeMessageBody;
        attachments = @($EmployeePfxAttachment)
    }

	Write-Log -Message "Sending PFX to user." -Type Debug
    Send-MgUserMail -UserId $PFXExportPasswordMailbox -Message $EmployeeMessage

    # Send export password to support mailbox
    $SupportEmailRecipient = @{
		emailAddress = @{
			address = $PFXExportPasswordMailbox
		}
	}
    $SupportHtmlHeader = "<h2>S/MIME Certificate Export Password</h2>"
    $SupportHtmlBody = "<p>Please find the export password for the PFX certificate of user $($User.AdditionalProperties.userPrincipalName)</p>
                        <p>Make sure that you share the password with the user through a different communication channel.</p>
						<p></p>
						<p>Password: $ExportPass"
    $SupportHtmlMsg = $SupportHtmlHeader + $SupportHtmlBody

    $SupportMessageBody = @{
        content = "$($SupportHtmlMsg)"
        ContentType = "html"
    }

    $SupportMessage = @{
        subject = "S/MIME Certificate Export Password";
        toRecipients = @($SupportEmailRecipient);
        body = $SupportMessageBody
    }

	Write-Log -Message "Sending PFX export password to Support Mailbox." -Type Debug
    Send-MgUserMail -UserId $PFXExportPasswordMailbox -Message $SupportMessage

    Write-Log -Message "Delete temp pfx cert" -Type Debug
    Remove-Item -Path "$($env:ProgramData)\baseVISION-SMIME\temp\export-cert.pfx" -Force

}
#endregion

#region Dynamic Variables and Parameters
########################################################

# Try get actual ScriptName
try {
    $CurrentFileNameTemp = $MyInvocation.MyCommand.Name
    If ($null -eq $CurrentFileNameTemp -or $CurrentFileNameTemp -eq "") {
        $CurrentFileName = "NotExecutedAsScript"
    }
    else {
        $CurrentFileName = $CurrentFileNameTemp
    }
}
catch {
    $CurrentFileName = $LogFilePathScriptName
}
$LogFilePath = "$LogFilePathFolder\{0}_{1}_{2}.log" -f ($ScriptName -replace ".ps1", ''), $ScriptVersion, (Get-Date -uformat %Y%m%d%H%M)
# Try get actual ScriptPath
try {
    try { 
        $ScriptPathTemp = Split-Path $MyInvocation.MyCommand.Path
    }
    catch {

    }
    if ([String]::IsNullOrWhiteSpace($ScriptPathTemp)) {
        $ScriptPathTemp = Split-Path $MyInvocation.InvocationName
    }

    If ([String]::IsNullOrWhiteSpace($ScriptPathTemp)) {
        $ScriptPath = $FallbackScriptPath
    }
    else {
        $ScriptPath = $ScriptPathTemp
    }
}
catch {
    $ScriptPath = $FallbackScriptPath
}

#endregion

#region Initialization
########################################################

if (!(Test-Path $LogFilePathFolder))
{
    New-Folder $LogFilePathFolder
}
if (!(Test-Path "$($env:ProgramData)\baseVISION-SMIME\Orders" ))
{
    New-Folder "$($env:ProgramData)\baseVISION-SMIME\orders"
    New-Folder "$($env:ProgramData)\baseVISION-SMIME\orders\rejected"
    New-Folder "$($env:ProgramData)\baseVISION-SMIME\orders\revoked"
    New-Folder "$($env:ProgramData)\baseVISION-SMIME\orders\canceled"
    New-Folder "$($env:ProgramData)\baseVISION-SMIME\orders\expired"
    New-Folder "$($env:ProgramData)\baseVISION-SMIME\orders\issued"
    New-Folder "$($env:ProgramData)\baseVISION-SMIME\temp"
}

Write-Log "Start Script $Scriptname"

Write-Log "Delete all log Files in C:\temp older than 30 day(s)"
$Daysback = "-30"
$CurrentDate = Get-Date
$DatetoDelete = $CurrentDate.AddDays($Daysback)
Get-ChildItem $LogFilePathFolder | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item -Force

Write-Log "Select MS Graph beta version"
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
        Scopes = @("User.Read.All","GroupMember.Read.All","DeviceManagementConfiguration.ReadWrite.All, Exchange.ManageAsApp, Mail.SendAs")
    }
}

try {
    Write-log -Type Info -message "Connecting to Azure AD ..."
    try {
        $context = Get-MgContext -ErrorAction Stop
        if($null -eq $context){
            throw "Not connected"
        }
        
    } catch {
        Connect-MgGraph @AADAuthBody 
    }

}
catch {
    Write-Log -Message "Get Token Failed" -Type Error -Exception $_.Exception
    throw "Get Token failed, stopping script."
}

try{
    Import-Module IntunePfxImport
} catch {
    Write-Log -Message "Failed to load 'IntunePfxImport'" -Type Error -Exception $_.Exception
    throw "Failed to load 'IntunePfxImport'"
}
if($EnableSharedMailboxSupport){
    Write-log -Type Info -message "Check Module ExOnline"
    $Module = Get-Module -Name ExchangeOnlineManagement -ListAvailable

    If ($Null -eq $Module){
        Write-log -Type Info -message "ExchangeOnlineManagement Module not installed"
    } else {
        Write-log -Type Info -message "ExchangeOnlineManagement Module found"
    }

    Write-log -Type Info -message "Connecting to Exchange Online ..."
    $tenantDomain = "basevision.onmicrosoft.com"
    Connect-ExchangeOnline -ManagedIdentity -Organization $tenantDomain

}

#endregion

#region Main Script
########################################################

# get all Users in Scope
try {
	# First we get all members of the group, including members of encapsulated groups
    [array]$allGroupMembers = (Get-MgGroupTransitiveMember -GroupId $ScopeGroupId -Property @("id","accountEnabled","displayName","mail","userPrincipalName","proxyAddresses","department"))
    # And filter out all group objects with the odata type
	[array]$allUsers = $allGroupMembers | Where-Object {$_.AdditionalProperties."@odata.type" -ne "#microsoft.graph.group" }
	Write-Log -Message "Successfully sourced users" -Type Info
}
catch {
    Write-Log -Message "It was not possible to get users" -Type Error -Exception $_.Exception
}

# get all PFX Certificates from Intune Service
try {
    [array]$AllUserPFXs = (Get-MgDeviceManagementUserPfxCertificate -All -Property @("id","expirationDateTime","userPrincipalName"))
    Write-Log -Message "Successfully sourced all PFX Certificates from Intune Service" -Type Info
}
catch {
    Write-Log -Message "It was not possible to get all PFX Certificates from Intune Service" -Type Error -Exception $_.Exception
}

# get all Shared Mailbox Permissions from Exo
if($EnableSharedMailboxSupport){
    $SharedMailBoxAccess = @()
    foreach($Mailbox in (Get-EXOMailbox -RecipientTypeDetails SharedMailbox)){

        foreach($Member in ($Mailbox | Get-EXOMailboxPermission)){
            $SharedMailBoxAccess += @{
                Mailbox = $Mailbox.UserPrincipalName
                User = $Member.User
            }
        }
    } 

}

foreach($User in $AllUsers){
    Write-Log -Message "Processing user '$($User.AdditionalProperties.userPrincipalName)'" -Type Debug
    # Check if user already has a valid certificate 
    $FoundCert = $AllUserPFXs | Where-Object { $_.UserPrincipalName -eq $User.AdditionalProperties.userPrincipalName -and $_.ExpirationDateTime.Date -gt (Get-Date).AddDays(-14) }

    if($null -eq $FoundCert){
        Write-Log -Message "No valid PFX found for user '$($User.AdditionalProperties.userPrincipalName)'" -Type Info
        Write-Log -Message "Checking for Pending Order '$($User.AdditionalProperties.userPrincipalName)'" -Type Debug
        if(Test-Path "$($env:ProgramData)\baseVISION-SMIME\Orders\$($User.Id).json"){
            Write-Log -Message "Pending Order '$($env:ProgramData)\baseVISION-SMIME\Orders\$($User.Id).json' found" -Type Info
            $OrderInfo = Get-Content -Path "$($env:ProgramData)\baseVISION-SMIME\Orders\$($User.Id).json" | ConvertFrom-Json
            $Status = Get-DigicertSmimeOrder -OrderId $OrderInfo.id
            if(@("rejected","revoked","canceled","expired") -contains $status ){
                Write-Log -Message "Order $status, Create new Request" -Type Warn
                Move-Item -Path "$($env:ProgramData)\baseVISION-SMIME\Orders\$($User.Id).json" -Destination "$($env:ProgramData)\baseVISION-SMIME\Orders\$status\$(Get-Date -Format "yyyyMMddHHmm")-$($User.Id).json" -Force
                $ProxyAddresses = $User.AdditionalProperties.proxyAddresses
                
                if($EnableSharedMailboxSupport){
                    $ProxyAddresses += ($SharedMailBoxAccess | Where-Object {$_.User -eq $User.AdditionalProperties.userPrincipalName}).Mailbox
                }
                $ProxyAddresses = $ProxyAddresses -replace "SMTP:",""
                New-DigicertSmimeOrder -UserId $User.Id -PrimaryMail $User.AdditionalProperties.mail -MailAliases $ProxyAddresses -DisplayName $User.AdditionalProperties.displayName
            } elseif($status -eq "issued"){
                Write-Log -Message "Order processed and issued. Importing signed cert." -Type Info
                $cert = Invoke-DigicertSmimeInstall -OrderId $OrderInfo.id
                Upload-PfxToIntune -Certificate $cert -Upn $User.AdditionalProperties.userPrincipalName

                if($EnablePFXExport) {
					Write-Log -Message "Order processed and issued. Sending PFX to employee per mail." -Type Info
					Send-PFXCertificate -Certificate $cert -User $User
				}
            } else {
                Write-Log -Message "Order status $status, do nothing until issued." -Type Info
            }
        } else {
            # Digicert Request
            Write-Log -Message "No Pending Order, start creating CSR" -Type Info
            $ProxyAddresses = $User.AdditionalProperties.proxyAddresses
            
            if($EnableSharedMailboxSupport){
                $ProxyAddresses += ($SharedMailBoxAccess | Where-Object {$_.User -eq $User.AdditionalProperties.userPrincipalName}).Mailbox
            }
            $ProxyAddresses = $ProxyAddresses -replace "SMTP:",""
            New-DigicertSmimeOrder -UserId $User.Id -PrimaryMail $User.AdditionalProperties.mail -MailAliases $ProxyAddresses -DisplayName $User.AdditionalProperties.displayName
        }

    } else {
        Write-Log -Message "PFX found for user '$($User.AdditionalProperties.userPrincipalName)' valid until '$($FoundCert.ExpirationDateTime)'" -Type Info
    }

}



#endregion

#region Finishing
########################################################

Write-log -message "Disconnecting Exchange Online Session" -Type Info
Disconnect-ExchangeOnline -Confirm:$false

Write-log -message "End Script $scriptname" -Type Info