# ITfoxtec.Identity.Saml2.Mvc

ITfoxtec.Identity.Saml2.Mvc adds ASP.NET MVC 5 integration helpers for [ITfoxtec.Identity.Saml2](https://www.nuget.org/packages/ITfoxtec.Identity.Saml2). Use it when a .NET Framework MVC application needs SAML 2.0 sign-on, logout, metadata, and binding handling without writing the MVC plumbing yourself.

The package is maintained by [FoxIDs](https://www.foxids.com). The ITfoxtec name remains in the package and namespaces for compatibility with existing integrations.

## What it adds

- Request conversion from ASP.NET MVC requests to SAML 2.0 requests.
- `ActionResult` helpers for Redirect, POST, Artifact, SOAP, and metadata responses.
- MVC-friendly integration points for SAML 2.0 login, assertion consumer service, single logout, and metadata endpoints.

The underlying SAML 2.0 implementation supports message signing, signature validation, encrypted assertions, metadata, Redirect Binding, POST Binding, Artifact Binding, Azure Key Vault certificate scenarios, RSA signing, signature algorithm and XML canonicalization validation allowlists, configurable AES-CBC/AES-GCM assertion encryption, RSA key encryption, XML Encryption 1.1 RSA-OAEP, and interoperability with Microsoft Entra ID (Azure AD), AD FS, Azure AD B2C, Danish NemLog-in3 (MitID), Danish Context Handler (Faelleskommunal Adgangsstyring), and other SAML 2.0 solutions.

## Supported frameworks

- .NET Framework 4.6.2
- .NET Framework 4.8

## Getting started

```powershell
Install-Package ITfoxtec.Identity.Saml2.Mvc
```

The package depends on [ITfoxtec.Identity.Saml2](https://www.nuget.org/packages/ITfoxtec.Identity.Saml2), which contains the protocol implementation. More information is available on the [project page](https://www.foxids.com/components/identitysaml2), in the [sample applications](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/development/test), and in the [GitHub source](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2).

## Direct integration or FoxIDs bridge

Use ITfoxtec.Identity.Saml2.Mvc when you need to implement SAML 2.0 directly in your ASP.NET MVC application.

If your application already supports OpenID Connect or WS-Federation, [FoxIDs](https://www.foxids.com) can be the cleaner integration point. FoxIDs handles the SAML 2.0 connection to the external identity provider or relying party, while the application continues to use the protocol it already supports. This can avoid adding another federation protocol implementation to the application.

Consider FoxIDs when you need:

- A [SAML 2.0 to OpenID Connect bridge](https://www.foxids.com/docs/bridge), or SAML 2.0 to WS-Federation bridge.
- SAML 2.0 integration without changing an application that already supports OpenID Connect or WS-Federation.
- Hosted or self-hosted federation infrastructure across SAML 2.0, OpenID Connect, OAuth 2.0, and WS-Federation.
- A place to operate protocol translation, certificates, metadata, and partner-specific federation configuration outside the application code.
- Architecture guidance or implementation support for SAML 2.0 migrations and complex federation setups.

FoxIDs uses ITfoxtec.Identity.Saml2 for SAML 2.0 protocol handling. The library and FoxIDs are complementary: use the package when SAML 2.0 belongs in your application, and use FoxIDs when SAML 2.0 is better handled as an external identity bridge or federation service.

## Support

Use [GitHub issues](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/issues) for bugs and feature requests. For implementation questions, use [Stack Overflow](https://stackoverflow.com/questions/tagged/itfoxtec-identity-saml2) with the `itfoxtec-identity-saml2` tag.

Implementation help, architecture guidance, and custom samples are available from [FoxIDs](https://www.foxids.com) by contacting [anders@foxids.com](mailto:anders@foxids.com).
