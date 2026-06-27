# ITfoxtec.Identity.Saml2

ITfoxtec.Identity.Saml2 is an open-source SAML 2.0 / SAML-P library for .NET applications that need to act as a Service Provider (SP), Relying Party (RP), or Identity Provider (IdP).

The package is maintained by [FoxIDs](https://www.foxids.com). The ITfoxtec name remains in the package and namespaces for compatibility with existing integrations.

## What it covers

- SAML 2.0 login, logout, single logout, and metadata.
- SP-initiated and IdP-initiated sign-on.
- Message signing, signature validation, and encrypted assertions.
- Redirect Binding, POST Binding, Artifact Binding, and SOAP support.
- Authn Request, Authn Response, Logout Request, and Logout Response handling.
- Signing and encryption certificates, including Azure Key Vault scenarios.
- RSA SHA1, SHA256, SHA384, SHA512, and RSA-PSS SHA256 message signing.
- ECDSA SHA256, SHA384, and SHA512 signing and signature validation on supported modern .NET targets.
- Signature algorithm and XML canonicalization validation allowlists for accepting multiple incoming signing profiles.
- Configurable assertion encryption with AES-CBC, AES-GCM, RSA key transport, and XML Encryption 1.1 RSA-OAEP support.
- Tested interoperability with Microsoft Entra ID (Azure AD), AD FS, Azure AD B2C, Danish NemLog-in3 (MitID), Danish Context Handler (Faelleskommunal Adgangsstyring), and other IdPs and RPs.

## Packages

| Package | Purpose |
| ------- | ------- |
| [ITfoxtec.Identity.Saml2](https://www.nuget.org/packages/ITfoxtec.Identity.Saml2) | Core SAML 2.0 protocol implementation. |
| [ITfoxtec.Identity.Saml2.MvcCore](https://www.nuget.org/packages/ITfoxtec.Identity.Saml2.MvcCore) | ASP.NET Core MVC integration helpers. |
| [ITfoxtec.Identity.Saml2.Mvc](https://www.nuget.org/packages/ITfoxtec.Identity.Saml2.Mvc) | ASP.NET MVC 5 integration helpers for .NET Framework. |

## Supported frameworks

- .NET 10.0
- .NET 9.0
- .NET 8.0
- .NET 7.0
- .NET 6.0
- .NET Standard 2.1
- .NET Framework 4.6.2 and 4.8

## Getting started

Install the core package:

```bash
dotnet add package ITfoxtec.Identity.Saml2
```

For ASP.NET Core MVC applications, install:

```bash
dotnet add package ITfoxtec.Identity.Saml2.MvcCore
```

For ASP.NET MVC 5 applications, install:

```powershell
Install-Package ITfoxtec.Identity.Saml2.Mvc
```

Start with the [project page](https://www.foxids.com/components/identitysaml2), [test samples](test), and the ASP.NET Core sample [TestWebAppCore](test/TestWebAppCore).

## Build and test

Restore and build the solution:

```bash
dotnet restore ITfoxtec.Identity.Saml2.sln
dotnet build ITfoxtec.Identity.Saml2.sln -c Release
```

Run the unit tests:

```bash
dotnet test UnitTest/ITfoxtec.Identity.Saml2.Tests/ITfoxtec.Identity.Saml2.Tests.csproj
```

Run the ASP.NET Core sample application:

```bash
dotnet run --project test/TestWebAppCore/TestWebAppCore.csproj
```

## Direct integration or FoxIDs bridge

Use ITfoxtec.Identity.Saml2 when you need to implement SAML 2.0 directly in your .NET or ASP.NET application.

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

## License

This project is released under the [BSD-3-Clause license](LICENSE).
