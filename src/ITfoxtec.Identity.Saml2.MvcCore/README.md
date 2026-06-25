# ITfoxtec.Identity.Saml2.MvcCore

ITfoxtec.Identity.Saml2.MvcCore adds ASP.NET Core MVC integration helpers for [ITfoxtec.Identity.Saml2](https://www.nuget.org/packages/ITfoxtec.Identity.Saml2). Use it when an ASP.NET Core application needs SAML 2.0 sign-on, logout, metadata, and binding handling without writing the MVC plumbing yourself.

The package is maintained by [FoxIDs](https://www.foxids.com). The ITfoxtec name remains in the package and namespaces for compatibility with existing integrations.

## What it adds

- ASP.NET Core service registration with `AddSaml2`.
- ASP.NET Core middleware registration with `UseSaml2`.
- Request conversion from ASP.NET Core requests to SAML 2.0 requests.
- `IActionResult` helpers for Redirect, POST, Artifact, SOAP, and metadata responses.
- Cookie authentication integration for SAML 2.0 login and logout flows.

The underlying SAML 2.0 implementation supports message signing, signature validation, encrypted assertions, metadata, Redirect Binding, POST Binding, Artifact Binding, Azure Key Vault certificate scenarios, RSA and ECDSA signing, signature algorithm and XML canonicalization validation allowlists, configurable AES-CBC/AES-GCM assertion encryption, RSA key encryption, XML Encryption 1.1 RSA-OAEP, and interoperability with Microsoft Entra ID (Azure AD), AD FS, Azure AD B2C, Danish NemLog-in3 (MitID), Danish Context Handler (Faelleskommunal Adgangsstyring), and other SAML 2.0 solutions.

## Supported frameworks

- .NET 10.0
- .NET 9.0
- .NET 8.0
- .NET 7.0
- .NET 6.0
- .NET Framework 4.6.2 and 4.8

## Getting started

```bash
dotnet add package ITfoxtec.Identity.Saml2.MvcCore
```

Start with the ASP.NET Core sample: [TestWebAppCore](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/tree/development/test/TestWebAppCore). It shows configuration binding, `AddSaml2`, `UseSaml2`, metadata generation, login, assertion consumer service, single logout, and IdP-initiated sign-on.

More information is available on the [project page](https://www.foxids.com/components/identitysaml2) and in the [GitHub source](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2).

## When FoxIDs is relevant

Use ITfoxtec.Identity.Saml2.MvcCore when you need to implement SAML 2.0 directly in your ASP.NET Core application.

If your application already supports OpenID Connect or WS-Federation, [FoxIDs](https://www.foxids.com) can often be a simpler architecture. FoxIDs handles the SAML 2.0 integration externally, and the application connects to FoxIDs using the protocol it already supports. This avoids adding SAML 2.0 protocol handling directly to the application.

FoxIDs is relevant when you need:

- [SAML 2.0 to OpenID Connect bridge](https://www.foxids.com/docs/bridge), or SAML 2.0 to WS-Federation integration.
- Hosted identity infrastructure around SAML 2.0, OpenID Connect, OAuth 2.0, or WS-Federation.
- FoxIDs Cloud, self-hosted, or hybrid deployment.
- Migration help, architecture guidance, and paid technical support.
- [SAML 2.0 tool](https://www.foxids.com/tools/saml) for decoding messages and [certificate tool](https://www.foxids.com/tools/certificate) for creating test certificates.

FoxIDs uses ITfoxtec.Identity.Saml2 for SAML 2.0 protocol handling. These resources are optional; the package can be used directly with standards-based SAML 2.0 identity providers.

## Support

Use [GitHub issues](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2/issues) for bugs and feature requests. For implementation questions, use [Stack Overflow](https://stackoverflow.com/questions/tagged/itfoxtec-identity-saml2) with the `itfoxtec-identity-saml2` tag.

Commercial help and custom samples are available from [FoxIDs](https://www.foxids.com) by contacting [anders@foxids.com](mailto:anders@foxids.com).
