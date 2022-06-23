# Introduction

The following manual helps to configure fully automated deployment of imported PKCS certificates from Digicert Cert Central. The Certificates are ordered via API and paid via credit card by default. Setting up a balance is also possible. The main goal is to deploy certificates for signing purposes and not for encryption as we are using Microsoft Pureview Information Protection for this use case.

This blog post is dedicated to the steps of the “Import Flow.”

## Import Flow

![](media/8b8a543ecf238d8c8a23a3843862e40c.png)

1: Admin creates key pair and certificate request

2: Admin sends Public Key with his identity to the CA PKCS\#10 / This can be any CA including Public one

3: The CA signs the Public key of the client with the CA private key. PKCS\#10

4: The CA returns the signed public key to NDES Service

5: Creating PFX file with self defined Password

6: PowerShell module Encrypt password of PFX cert with public key of connector certificate  
 --- Create Public / Private key (Could be hsm or Win Software key Storage Provider

\--- Build PowerShell module available on Github

\--- \$userPFXObject = New-IntuneUserPfxCertificate -PathToPfxFile "\<FullPathToPFX\>" \$SecureFilePassword "\<UserUPN\>" "\<ProviderName\>" "\<KeyName\>" "\<IntendedPurpose\>" "\<PaddingScheme\>" "\<File path to public key file\>"

7 upload PFX file

8 upload encrypted password

## Deployment Flow

![](media/b6e1b594d5bbdb1b716a83ae286b0962.png)

1 Request Policy

2: Intune requests Certificate connector

\-- Sends encrypted PFX password, PKCS\#12 certificate and devices public key

3: decryptes PFX password & reencrypts PFX password with device public key

4 Sends re-encrypted PFX password, PKCS\#12 certificate to intune

5: Device gets certificate via policy

6: Client decrypts certificate by using device management certificate

# Setup Digicert

It’s not simple to get the correct information from certificate providers on how to deploy SMIME certs. In general, the account teams do not seem to have knowledge about certificates or mdm deployment and reference to SSL certificates. But Digicert was able to help and therefore they were chosen for this implementation.

1.  Setup Cert Central account setup.  
    [Sign up for your DigiCert account](https://www.digicert.com/account/signup/)
2.  Then contact your Account manager and request, that they add the specific SMIME certificate products to your account. By default, only a small subset of their products can be ordered. If you need a lot of certificates, then you can also try to get discounts. Verify if you can see the products here:  
    ![A screenshot of a computer Description automatically generated](media/ac6c0c1928e6d5ad88262ff652967f3b.png)  
      
    By default we use a Premium template as it can be used also for document signing and authentication (VPN/Wifi). You could also choose another template by adjusting the script(Variable Definition).
3.  Add a credit card as payment method. If you would like to use another method like balance or invoice you have to adjust the scripts and Cert Central Config.  
    ![](media/fd8dc3fd1981e48e5d0ca3d1189425a1.png)
4.  Create an API Key with a restriction to Orders. The key should be saved securely as we require it later   
    ![Graphical user interface, text, application Description automatically generated](media/a9fe1b13411b4005a48bbaf7c60f7205.png)
5.  Make a note of the organization id which you would like to use.  
    ![Graphical user interface, application Description automatically generated](media/f5c3a58158f81770f6e31274a594a8e8.png)

# Prepare your infrastructure

## Setup Azure VM in a new resource group.

To execute the script we require Virtual Machine with the Intune certificate Connector installed. The creation of a virtual machine in azure should be a simple step, but I recommend to enable the following features to have the private keys stored securely:

-   Enable TPM during setup
-   Enable Only RDP and a public IP only when there are not internal routings available. If it is required, then we highly recommend enabling Just-In-Time-Access
-   You can if you like join the VM to your domain and we recommend to think about how the VM will be managed in the future regarding Security Baselines and Updates.

![](media/cfbe195d75fc8cf133efac3d1f3f8096.png)

![Graphical user interface, text, application Description automatically generated](media/76bcf716de0978c8853f88f1f75bca94.png)

### Install Intune Certificate Connector

Then you need to connect to the VM via RDP and install the Intune Certificate Connector.

1.  Connect to the VM
2.  Browse to <https://endpoint.microsoft.com> Tenant Admin Certificate Connectors
3.  Click in Add to get the Download offered  
    ![Graphical user interface, text, application, email Description automatically generated](media/b087f610c3e5871dea0d5d12c2101a2f.png)
4.  Download the connector  
    ![Graphical user interface, text, application, email Description automatically generated](media/79aea0fcea2983a9858a463361e0d167.png)
5.  Start installing the connector by agreeing to the T&C and click on install  
    ![Graphical user interface, text, application, email Description automatically generated](media/14d2df6ddbcc48a38b804c9e9d33ac06.png)
6.  Choose “configure now” to start the configuration  
    ![Graphical user interface, text, application, email Description automatically generated](media/cf1bb6680503054a2945de5a74da3978.png)
7.  Select next  
    ![Graphical user interface, text, application, email Description automatically generated](media/0933c563bc2a4cb5668e017b3dd2def2.png)
8.  Select “PKCS imported certificates” and click on next  
    ![Graphical user interface, text, application, email Description automatically generated](media/42b66f4f1e1b06ae4b03d60926381ce0.png)
9.  You can choose to use any Service Account but in normal cases we use the system account.  
    ![Graphical user interface, text, application, email Description automatically generated](media/67f5d068b87ef2cbde2708f2d8119911.png)
10. Configure a Proxy if it is required within your environment.  
    ![Graphical user interface, text, application, email Description automatically generated](media/8ba17b738ff0373d817992c4bcc5ff5c.png)
11. If all prerequisites are fulfilled click on next.  
    ![Graphical user interface, text, application Description automatically generated](media/b7159d468ed805bc35e7941ad4e77829.png)
12. Sign in with Intune Administrator or Global Administrator Credentials.   
    ![Graphical user interface, text, application Description automatically generated](media/39cc1c2466464fd801c3811895d71d5e.png)
13. The connector is now fully configured and therefore you can click on Exit.  
    ![Graphical user interface, text, application Description automatically generated](media/63b8ef715acdbda0d6bbf995cedf1023.png)

### VM Manged Identity and Microsoft Graph Permissions

1.  Enable System Managed Identity on the Azure Virtual Machine  
    ![Graphical user interface, application Description automatically generated](media/60dab5a55a021710d0763b2150b56ba3.png)
2.  Grant the permissions via Script by executing the SetupAAD.ps1 script from the script repo. Specify the Object ID retrieved from the previous screen on the first line of the script.  
    ![Graphical user interface, application Description automatically generated](media/bb3dfa9d7548534fc8c86e9a747500c7.png)

### Install PowerShell Modules

To execute the solution various PowerShell Modules should be preinstalled on the host and a Private/Public-Key needs to be created.

1.  Copy the Setup.ps1 and the IntunePfxImport folder to the VM
2.  Execute the setup.ps1  
    It will install all required modules and generate an encryption key which will then be used by the Intune Connector and the script.

Note: The IntunePfxImport Module is a ready to use build based on the Microsoft solution. Microsoft has not published this module to the PowerShellGallery and requires everybody to build with visual studio. To simplify this was done once for baseVISION. More Information in section “(Optional) Build IntunePfxImport Module” in the Appendix.

## Setup Azure Automation Account

We have now prepared the Virtual machine which will be used to execute the solution. Now we configure the solution to Automate and monitor the solution.

1.  Create a new Azure Automation Account within your environment. We suggest using the same resource group like for the VM.  
    ![](media/fc3bfe8b797ea16149ba0cc80e63937a.png)
2.  You can unselect the “System assigned” identity as the one of the VM is used.  
    ![](media/63bb69dff39fe12bc880966e3addc9bd.png)
3.  The Azure Automation Account requires Internet Access and therefore in normal Case Public Access should be chosen.  
    ![](media/018886d85e8775a65f224713e9b7cd94.png)
4.  Assign Tags based on your requirements.  
    ![](media/e338c6c3f4b6689a1f389899758c235f.png)
5.  Validate all settings and click on “create” when ready  
    ![](media/3edd933d1342d2ad7847e13acf5ba814.png)
6.  As soon the resource is created select “Go to resource” and switch to the Variables section and define the variables:
    1.  Use the DigiCertApiKey and DigiCertOrgId collected in the previous section. As DigiCertProduct you can choose from the following list of types:
-   client_premium - Premium
-   client_digital_signature_plus - Digital Signature Plus
-   client_authentication_plus - Authentication Plus
-   client_email_security_plus - Email Security Plus
-   class1_smime - Class 1 S/Mime Certificate

    Source: <https://dev.digicert.com/services-api/orders/order-client-certificate/>

    1.  For the AADScopeGroupId retrieve the object id from a Azure AD group which defines the scope of the deployment and contains user accounts.
    2.  The value of EnableSharedMailboxSupport depends on your requirements. If the user should also have the mail addresses of shared mailboxes where he has access on time of certificate request, then set it to true otherwise to false.  
        If you set the value to true then follow also the steps in the section Shared Mailbox Support.
    3.  The TenantName should contain the .onmicrosoft.com name of your tenant

        ![Graphical user interface, application Description automatically generated](media/d8c503e59d0ce000a58af72afbf49c65.png)

### Configure the created VM as Hybrid Worker

Now we have to provision the VM as a hybrid worker in our Azure Automation Account.

1.  In the Azure Automation Account select “Hybrid Worker Groups” in the menu
2.  Create a new group by providing a name for it. I use “IntuneConnector”  
    ![](media/faf2d5eae3f2577e0a182788e31856fe.png)
3.  Select “Add machines” on the next screen  
    ![](media/249d82ecd7c217d51324501402b57d65.png)
4.  You can simply select the created VM. If you like to use an on-premises VM you have to follow the instructions, then follow Microsoft docs on how to setup them.   
    ![Graphical user interface, text, application, email Description automatically generated](media/f81f2d7365b7bbc7a5c96adabb5b7204.png)
5.  When the correct VM is selected choose “Review + Create” and start the creation when everything looks ok.   
    ![Graphical user interface Description automatically generated](media/0b5b5fed8902c6b2eeaba5144fdf5c14.png)

### Setup Runbook CertificateRequestor

Now we have to create the Runbook.

1.  Start by selecting “Runbooks” within the console and click on “Create a runbook” to start the process.
2.  Provide a name and select PowerShell as Runbook type and select 5.1 as runtime version.  
    ![](media/a3dedc8dc7351cb6a8d2b70e81c00ade.png)
3.  Copy the script from the repo to the content pane and then publish it.   
    ![Graphical user interface, text Description automatically generated](media/25b8e4704e04e800475adfea877ec0fa.png)

### Enable Shared Mailbox Support (Optional)

In case users should receive a certificate, which includes the primary mailbox address of assigned shared mailboxes, then a few special configuration steps are required.

Configure a Run As Account for Azure Automation as the Exchange Online PowerShell module does not support managed identities.

1.  Select “Run as accounts” in the menu and generate a “Azure Run As Account”  
    ![Graphical user interface, text, application, email Description automatically generated](media/81f8527d75fda223b9a28ce77dae298b.png)
2.  Click on create   
    ![Graphical user interface, text, application Description automatically generated](media/d9d759609729ea93c292c5d0850a8092.png)
3.  Now select the new account  
    ![Graphical user interface, text, application, email Description automatically generated](media/06093b27de0697c291f94a87cd712d8a.png)
4.  And copy the Object id as it is required to grant the permissions.   
    ![Graphical user interface, text, application, email Description automatically generated](media/4f322940f1dfd1927e5316451144be13.png)
5.  Then insert the Object Id in the “SetupExo.ps1” and execute the script with Global Admin permissions.
6.  Then modify the “\$EnableSharedMailboxSupport” variable in the CertificateRequestor Runbook to \$true
7.  Create an new Runbook to import the RunAsCertificate to the Hybrid Worker as [documented by Microsoft](https://docs.microsoft.com/en-us/azure/automation/automation-hrw-run-runbooks?tabs=sa-mi#runas-script).

## Exchange Online Configuration

DigiCert is sending a confirmation mail including the certificate to the user when the order is processed. This could be confusing for the user as he does not have the corresponding private key as it was generated on the hybrid worker.

![Graphical user interface, text, application, email Description automatically generated](media/af35fe10d4ee7b3347ca8da91d914448.png)

Therefore, a transport rule could be used to block these messages.

1.  Go to <https://admin.microsoft.com> and navigate to the Exchange Admin Center.  
    ![Graphical user interface, application, Teams Description automatically generated](media/6f1c7382d980ce027b291deed7549ec6.png)
2.  Select “Mail Flow” and then “Rules”  
    ![Graphical user interface, application, Teams Description automatically generated](media/dbbccb560cc297b75a9ea9e4ee7f9cff.png)
3.  Create a new Rule  
    ![Graphical user interface, text, application Description automatically generated](media/0e92d89b2a15689c9f2ac06d5dede42f.png)
4.  And use the following values. In case you wish you could also forward the message to a specific mailbox instead of deleting the mails completely.  
    ![Graphical user interface, application Description automatically generated](media/a5a7347b7fb9db411aaa116e8e08d8b8.png)

## Test the implementation

1.  Testing the implementation is an important step are there are many possibilities for mistakes.
2.  Open the Runbook  
    ![Graphical user interface, application, Word Description automatically generated](media/8174d11e903bed97d07864724c801bbb.png)
3.  Select Edit  
    ![Graphical user interface, text, application, email Description automatically generated](media/c8433a58b9291fa71966c236a2a047c5.png)
4.  Select “Test pane”  
    ![](media/c6adfe82b22a35d3823147c92e5a98f3.png)
5.  Execute the script by selecting the correct hybrid worker group  
    ![Graphical user interface, application Description automatically generated](media/6ba20a1a00a6ff518b56600609337357.png)
6.  Follow the logs as defined in the appendix to troubleshoot issues if there are any. Keep in mind that one execution is required to create the order, then the user needs to validate the mail address and after that the next execution will upload the pfx to Intune.

## Enable Production Schedule

As soon the tests are successful you can create a schedule to execute the script as often as required.

1.  Open the Runbook “CertificateRequestor”
2.  Click on “Link to Schedule”  
    ![Graphical user interface, text, application, email Description automatically generated](media/bf37f5b2a2af0d959ed211ee795a0025.png)
3.  Click on Schedule  
    ![Graphical user interface, application, Word Description automatically generated](media/db838d5cdfceca10db74457e5858bb7d.png)
4.  Add a new schedule or choose from an existing one if there is one  
    ![Graphical user interface, application, Teams Description automatically generated](media/e4ca5c3e57cc40f9993e5ece79ccbec9.png)
5.  Then we need to define the Run settings  
    ![Graphical user interface, application, Word Description automatically generated](media/81f8ff1ee8f9e5b3fce635a9304364a6.png)
6.  Select “Hybrid Worker” and the created hybrid worker group and click on ok  
    ![Graphical user interface, application, Teams Description automatically generated](media/408dec66ece4acff5cd52cbf71f345c3.png)

# Example User Flow

As soon you add users to the AAD Group specified in step “Setup Azure Automation Account” and the Runbook is executed a new certificate order will be placed.

![Graphical user interface, text, application Description automatically generated](media/f6ac9dcf883e558c3e18958e813b3d7a.png)

On the hybrid worker you will find a reference to the pending order in the Program Data. The name of the file is the object id of the Azure AD User:

![Graphical user interface, text, application Description automatically generated](media/63f1745da77968584be436e4fc6144fd.png)

The user receives a Email Validation like:

![Graphical user interface, text, application, email Description automatically generated](media/d10387e130f498b33a32ffb5ef009596.png)

When all mail addresses are validated, and the Runbook is executed again, then the order will be finished.

In case you would like to see which mail, addresses are not validated or cancel the order, then you can do this directly in Digicert CertCentral via “Certificate Actions”. If you cancel the order, then the file will be moved to the canceled folder on the VM and a new request will be placed.

![Graphical user interface, text, application, email Description automatically generated](media/144be2473ad0f13741ce24f22d2b927f.png)

# Appendix

## Troublshooting – Delete Certificate from Intune to request new certificate from Digicert

In troubleshooting cases it’s sometimes helpful to be able to delete a certificate and request a new one. Keep in mind that this is associated with costs.

You can execute the RemoveCertificateFromIntune.ps1 script which will display a window to select the certificate which should be deleted.

## Troubleshooting – Log files

On the hybrid worker a log file per execution with detailed information is created.

![Graphical user interface, text, application, email Description automatically generated](media/75e3a087d4769bc8447d824935e92312.png)

It is also possible to have all logs including verbose/debug written to the Job log in Azure Automation which requires enabling it in the Azure Automation account. Errors are always logged in both places.

## (Optional) Build IntunePfxImport Module

Clone Git Repo [microsoft/Intune-Resource-Access: Sample code and scripts for interfacing with the Intune Resource Access APIs. (github.com)](https://github.com/Microsoft/Intune-Resource-Access)

![](media/8b8a3eef477e3c4a7fc67a0eb001581d.png)

![](media/61f222a4c94fd874fae1991c35fd1d25.png)
