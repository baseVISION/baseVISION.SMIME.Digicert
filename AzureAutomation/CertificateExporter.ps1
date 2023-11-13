<#
.DESCRIPTION
This add-on script is able to export SMIME/Client Auth certificates stored on the local system. 
This allows us to manually export SMIME certificates for specific users through mail messages.
    - The certificate with private key will be sent to the user.
    - The export password for said certificate will be sent to another, prefferably support, mailbox

The Managed Identity of the VM requires:
(Same permissions as for the certificate requestor script)
 - MSGraph
   - User.Read.All
   - (GroupMember.Read.All)
   - (DeviceManagementConfiguration.ReadWrite.All)
   - Send.Mail 

Setup
 - Setup an Azure Automation Account
 - Setup the script and Automation Variables
 - Alter the Azure VM Public IP Address to your specific configuration


.EXAMPLE


.NOTES
Author: Jan Büttiker/baseVISION
Date:   15.09.2022

History
    001: First Version

ExitCodes:
    99001: Could not Write to LogFile
    99002: Could not Write to Windows Log
    99003: Could not Set ExitMessageRegistry
#>


[CmdletBinding()]
Param(
    # Get User UPN of whom we want to export the certificate
    [Parameter (Mandatory= $true)]
    [String] $UserUPN,
    # Manually override Mailbox to which the export password will be sent to
    # If nothing defined, use automation-variable
    [Parameter (Mandatory= $false)]
    [String] $OverridePasswordExportMailbox
)

## Manual Variable Definition
########################################################
$DebugPreference = "Continue"
$ScriptVersion = "001"
$ScriptName = "CertificateExporter"

$LogFilePathFolder = "$($env:ProgramData)\baseVISION-SMIME\Logs"
$FallbackScriptPath = "C:\Windows" # This is only used if the filename could not be resolved(IE running in ISE)

# Log Configuration
$DefaultLogOutputMode = "Console-LogFile" # "Console-LogFile","Console-WindowsEvent","LogFile-WindowsEvent","Console","LogFile","WindowsEvent","All"
$DefaultLogWindowsEventSource = $ScriptName
$DefaultLogWindowsEventLog = "CustomPS"

# Azure VM with Managed Identity
$RunningInAzureVM = $true
$PFXExportPasswordMailbox = Get-AutomationVariable -Name 'PFXExportPasswordMailbox'
$ConfluenceDocPage = Get-AzAutomationVariable -Name 'ConfluenceDocPage'

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
			address = $User.userPrincipalName
		}
	}
    $EmployeeHtmlHeader = "<h2>Your S/MIME certificate</h2>"
    $EmployeeHtmlBody = "<p>Please find the PFX of your S/MIME certificate attached with this mail.</p>
                 <p>To import the PFX to your non-managed device, please contact $PFXExportPasswordMailbox so they can share the export password with you.
                 <p></p>
                 <p>For further instruction concerning Installation on non-MDM devices or certificate renewal, check out this <a href='$ConfluenceDocPage'>Confluence page</a></p>"
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
    $SupportHtmlBody = "<p>Please find the export password for the PFX certificate of user $($User.userPrincipalName)</p>
                        <p>Make sure that you save the password to Zoho Vault and grant password access to the user.</p>
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
if (!(Test-Path "$($env:ProgramData)\baseVISION-SMIME\temp" ))
{
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
        Scopes = @("User.Read.All","Mail.Send")
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
    Import-Module -Name Microsoft.Graph.Users.Actions
} catch {
    Write-Log -Message "Failed to load 'Microsoft.Graph.Users.Actions'" -Type Error -Exception $_.Exception
    throw "Failed to load 'Microsoft.Graph.Users.Actions'"
}

#endregion

#region Main Script
########################################################

# Get user from upn parameter 
try {
    $user = (Get-MgUser -ConsistencyLevel eventual `
                -Count userCount  -Top 1 `
                -Filter "startsWith(UserPrincipalName, '$UserUPN')" `
                -Property @("id","accountEnabled","displayName","mail","userPrincipalName","department"))
    Write-Log "Got user object from Azure AD"
    Write-Log $user -Type Info
}
catch {
    Write-Log -Message "It was not possible to get users" -Type Error -Exception $_.Exception
}

# Get certificate and send mail message
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$UserUPN*"}
    Write-Log -Message "Got user's PKCS certificate in local store" -Type Info
    Write-Log -Message $cert -Type Debug
    Send-PFXCertificate -Certificate $cert -User $user
} catch {
    Write-Log -Message "Not possible to retrieve certificate" -Type Error -Exception $_.Exception
}
