# Repository Guidelines

## Project Structure & Module Organization
Solution `ITfoxtec.Identity.Saml2.sln` ties together three library projects stored in `src/` (core library plus ASP.NET MVC and ASP.NET Core MVC helpers). Sample and verification sites live in `test/` (e.g., `TestWebAppCore`, `TestIdPCore`, Key Vault demos) and mirror hosting models to reproduce IdP/RP conversations before publishing packages. NuGet artifacts are emitted only from the library folders; keep sample-specific assets there to avoid polluting the shipping assemblies.

## Build, Test, and Development Commands
- `dotnet restore ITfoxtec.Identity.Saml2.sln` - fetches every target framework dependency.
- `dotnet build ITfoxtec.Identity.Saml2.sln -c Release` - runs multi-targeted builds and produces signed binaries.
- `dotnet pack src/ITfoxtec.Identity.Saml2/ITfoxtec.Identity.Saml2.csproj -c Release` - prepares the NuGet package used for public releases.
- `dotnet run --project test/TestWebAppCore/TestWebAppCore.csproj` - exercises SP initiated, redirect, and post bindings locally.

## Coding Style & Naming Conventions
Use 4-space indentation, braces on new lines, and `PascalCase` for public types/members. Locals stay `camelCase`, while persistent private fields use `_camelCase`. Keep namespaces explicit (`ITfoxtec.Identity.Saml2.*`) so bindings, cryptography helpers, and MVC extensions remain discoverable. Retain XML doc comments on public APIs; warnings `1591` and `1573` are suppressed only when documentation exists. Prefer guard clauses such as `ArgumentNullException(nameof(config))` and run `dotnet format` (or the equivalent IDE formatter) before submitting work.

## Testing Guidelines
Automated coverage lives in `UnitTest/` and should be extended for behavior-changing library changes. Add focused xUnit tests for cryptography, bindings, metadata, validation, and protocol edge cases before relying on sample apps for broader regression checks. Keep the unit test project wired into `ITfoxtec.Identity.Saml2.sln`; use `dotnet test UnitTest/ITfoxtec.Identity.Saml2.Tests/ITfoxtec.Identity.Saml2.Tests.csproj` for the fast unit test pass and run the full solution test when local Visual Studio web targets are available. Follow the existing `Test<Context><Host>` naming pattern for any new runnable sample scenario in `test/`. Capture manual test notes covering IdP metadata, signing certificates, Key Vault references, and RelayState expectations inside the relevant `test/*` README.

## Security & Configuration Tips
Do not commit secrets or real certificates. Sample apps should load configuration via environment variables, `dotnet user-secrets`, or Azure Key Vault, matching the `TestWebAppCoreAzureKeyVault` example. When sharing traces, sanitize assertions, entity IDs, and thumbprints. Validate new bindings against trusted IdPs (Azure AD, AD FS, NemLog-in) before merging to avoid regressions for both SP and IdP consumers.
