# ITfoxtec.Identity.Saml2

The ITfoxtec Identity Saml2 package adds SAML-P support for both Identity Provider (IdP) and Relying Party (RP).

* **Support .NET 8.0**
* **Support .NET 7.0**
* **Support .NET 6.0**
* **Support .NET 5.0**
* **Support .NET Core 3.1**
* **Support .NET Standard 2.1**
* **Support .NET Framework 4.6.1 and 4.7.2**

The ITfoxtec Identity Saml2 package implements the most important parts of the SAML-P standard and some optional features. 
Message signing and validation as well as decryption is supported. The package supports SAML 2.0 login, logout, single 
logout and metadata. Both SP Initiated and IdP Initiated sign on is supported.  
The package supports redirect binding, post binding and artifact binding.

> ## SAML 2.0 to OpenID Connect 1.0 bridge
> You can create a tenant on <a href="https://www.foxids.com">FoxIDs</a> and translate from SAML 2.0 to OpenID Connect. 
> FoxIDs handles the [SAML 2.0](https://www.foxids.com/docs/up-party-saml-2.0) traffic to the Identity Provider (IdP) and your application connects to FoxIDs with [OpenID Connect](https://www.foxids.com/docs/down-party-oidc).  
> *SAML 2.0 is an old standard with its shortcomings, and therefore it is often a better choice to use OpenID Connect in an application.*  
> You can likewise use FoxIDs to translate from the Danish [NemLog-in3 (MitID)](https://www.foxids.com/docs/up-party-howto-saml-2.0-nemlogin) and [Context Handler](https://www.foxids.com/docs/howto-saml-2.0-context-handler) to OpenID Connect.

The ITfoxtec Identity Saml2 package supports signing/encryption certificates in Azure Key Vault. 
Please see the [TestWebAppCoreAzureKeyVault](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/master/test/TestWebAppCoreAzureKeyVault) sample. 

The ITfoxtec Identity Saml2 package is tested for compliance with AD FS, Azure AD, Azure AD B2C, the Danish NemLog-in3 (MitID), the Danish Context Handler and many other IdPs and RPs.

Please see the [test samples](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/master/test").
The [TestWebAppCoreNemLogin3Sp](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/master/test/TestWebAppCoreNemLogin3Sp) sample show how to implement an NemLog-in3 Service Provider (SP).

> You can use the [SAML 2.0 tool](https://www.foxids.com/tools/Saml) to decode tokens and create self-signed certificates with the [certificate tool](https://www.foxids.com/tools/Certificate).

### More information
You can read more on [ITfoxtec Identity Saml2 Project Home Page](https://itfoxtec.com/identitysaml2).

### Support
If you have questions please ask them on <a href="https://stackoverflow.com/questions/tagged/itfoxtec-identity-saml2">Stack Overflow</a>. Tag your questions with 'itfoxtec-identity-saml2' and I will answer as soon as possible.

### Open source donations by PayPal 
[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/donate/?hosted_button_id=QVQN5ZNP2RK4Y)