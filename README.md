# ITfoxtec.Identity.Saml2

The ITfoxtec Identity Saml2 package adds SAML-P support for both Identity Provider (IdP) and Relying Party (RP).

* **Support .NET 5.0**
* **Support .NET Core 3.1**
* **Support .NET Standard 2.1**
* **Support .NET Framework 4.6.1 and 4.7.2**

The ITfoxtec Identity Saml2 package implements the most important parts of the SAML-P standard and some optional features. 
Message signing and validation as well as decryption is supported. The package supports SAML 2.0 login, logout, single 
logout and metadata. Both SP Initiated and IdP Initiated sign on is supported. 

The ITfoxtec Identity Saml2 package support signing/encryption certificates in Azure Key Vault. Please see the [TestWebAppCoreAzureKeyVault](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/master/test/TestWebAppCoreAzureKeyVault) sample in the [test](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/master/test) folder. 

The ITfoxtec Identity Saml2 package is tested for compliance with AD FS, Azure AD and Azure AD B2C. 

The ITfoxtec Identity Saml2 package support Danish NemLog-in 2 / OIOSAML 2 and NemLog-in 3 / OIOSAML 3 from version 4.6.1.  
The [TestWebAppCoreNemLogin3Sp](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/master/test/TestWebAppCoreNemLogin3Sp) sample application is configured with NemLog-in 3 and show how to implement a NemLog-in 3 Service Provider (SP).

### More information
You can read more on <a href="https://itfoxtec.com/identitysaml2">ITfoxtec Identity Saml2 Project Home Page</a>.

### Support
If you have questions please ask them on <a href="https://stackoverflow.com/questions/tagged/itfoxtec-identity-saml2">Stack Overflow</a>. Tag your questions with 'itfoxtec-identity-saml2' and I will answer as soon as possible.
