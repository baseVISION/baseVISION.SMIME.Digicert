# Setup Digicert

It’s not simple to get the correct information from certificate providers on how to deploy SMIME certs. In general, the account teams do not seem to have knowledge about certificates or mdm deployment and reference to SSL certificates. But Digicert was able to help and therefore they were chosen for this implementation.

1. Setup Cert Central account setup.  
    [Sign up for your DigiCert account](https://www.digicert.com/account/signup/)
2. Then contact your Account manager and request, that they add the specific SMIME certificate products to your account. By default, only a small subset of their products can be ordered. If you need a lot of certificates, then you can also try to get discounts. Verify if you can see the products here:  
    ![Orders view](media/ac6c0c1928e6d5ad88262ff652967f3b.png)  

    By default we use a Premium template as it can be used also for document signing and authentication (VPN/Wifi). You could also choose another template by adjusting the script(Variable Definition).
3. Add a credit card as payment method. If you would like to use another method like balance or invoice you have to adjust the scripts and Cert Central Config.  
    ![Check Payment](media/fd8dc3fd1981e48e5d0ca3d1189425a1.png)
4. Create an API Key with a restriction to Orders. The key should be saved securely as we require it later
    ![API page](media/a9fe1b13411b4005a48bbaf7c60f7205.png)
5. Make a note of the organization id which you would like to use.  
    ![Organization view](media/f5c3a58158f81770f6e31274a594a8e8.png)

As Digicert is now configured, [continue with your infrastructure](PrepareInfrastructure.md).
