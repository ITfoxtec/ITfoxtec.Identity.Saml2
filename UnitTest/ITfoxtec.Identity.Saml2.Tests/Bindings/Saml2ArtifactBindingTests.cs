using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Security;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Tests.Bindings
{
    public class Saml2ArtifactBindingTests
    {
        private const string IdpIssuer = "https://idp.example.test";
        private const string SpIssuer = "https://sp.example.test";
        private const string Subject = "user@example.test";
        private static readonly XNamespace Soap = Saml2Constants.SoapEnvironmentNamespaceX;
        private static readonly XNamespace Protocol = Saml2Constants.ProtocolNamespaceX;
        private static readonly XNamespace Extension = "urn:test:extension";

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task ResolveAsync_AcceptsSignedArtifactResponse(bool includeExtension)
        {
            using var certificate = CreateCertificate();
            var idp = new Saml2Configuration { Issuer = IdpIssuer, SigningCertificate = certificate };
            var artifact = new Saml2ArtifactResponse(idp, CreateLogin(idp));
            if (includeExtension)
            {
                artifact.Extensions = new Schemas.Extensions();
                artifact.Extensions.Element.Add(new XElement(Extension + "Response"), new XElement(Extension + "Assertion"));
            }
            var envelope = XElement.Parse(new Saml2SoapEnvelope().Bind(artifact).SoapResponseXml, LoadOptions.PreserveWhitespace);
            envelope.AddFirst(new XElement(Soap + "Header", new XElement(Extension + "Body"), new XElement(Extension + "Fault")));

            var result = await ResolveAsync(envelope, certificate);

            Assert.Equal(Subject, Assert.IsType<Saml2AuthnResponse>(result.InnerRequest).NameId.Value);
        }

        [Fact]
        public async Task ResolveAsync_AcceptsSignedDirectAssertion()
        {
            using var certificate = CreateCertificate();
            var idp = new Saml2Configuration
            {
                Issuer = IdpIssuer,
                SigningCertificate = certificate,
                AuthnResponseSignType = Saml2AuthnResponseSignTypes.SignAssertion
            };
            var login = CreateLogin(idp);
            var signedLogin = new Saml2PostBinding().Bind(login).XmlDocument;
            var artifact = new Saml2ArtifactResponse(new Saml2Configuration { Issuer = IdpIssuer }, login);
            var envelope = XElement.Parse(new Saml2SoapEnvelope().Bind(artifact).SoapResponseXml, LoadOptions.PreserveWhitespace);
            envelope.Descendants(Protocol + "Response").Single().ReplaceWith(XElement.Parse(signedLogin.OuterXml, LoadOptions.PreserveWhitespace));

            var result = await ResolveAsync(envelope, certificate);

            Assert.Equal(Subject, Assert.IsType<Saml2AuthnResponse>(result.InnerRequest).NameId.Value);
        }

        [Theory]
        [InlineData("Body", "nested")]
        [InlineData("Body", "foreign")]
        [InlineData("Body", "duplicate")]
        [InlineData("Response", "nested")]
        [InlineData("Response", "foreign")]
        [InlineData("Response", "duplicate")]
        [InlineData("Assertion", "nested")]
        [InlineData("Assertion", "foreign")]
        [InlineData("Assertion", "duplicate")]
        public async Task ResolveAsync_RequiresOneDirectChildInExpectedNamespace(string name, string structure)
        {
            var idp = new Saml2Configuration { Issuer = IdpIssuer };
            var artifact = new Saml2ArtifactResponse(idp, CreateLogin(idp));
            var envelope = XElement.Parse(new Saml2SoapEnvelope().Bind(artifact).SoapResponseXml);
            var element = envelope.Descendants().Single(child => child.Name.LocalName == name);
            switch (structure)
            {
                case "nested":
                    element.ReplaceWith(new XElement(Extension + "Wrapper", element));
                    break;
                case "foreign":
                    element.Name = Extension + name;
                    break;
                case "duplicate":
                    element.AddAfterSelf(new XElement(element));
                    break;
            }

            await Assert.ThrowsAsync<Saml2RequestException>(() => ResolveAsync(envelope));
        }

        [Fact]
        public async Task ResolveAsync_RejectsUnsignedResponseInsideValidArtifactSignature()
        {
            using var certificate = CreateCertificate();
            var idp = new Saml2Configuration { Issuer = IdpIssuer };
            var document = new Saml2ArtifactResponse(idp, CreateLogin(idp)).ToXml();
            var root = document.DocumentElement!;
            var login = root["Response", Protocol.NamespaceName]!;
            root.RemoveChild(login);

            var signer = new Saml2SignedXml(root, certificate,
                Saml2SecurityAlgorithms.RsaSha256Signature, SignedXml.XmlDsigExcC14NTransformUrl);
            signer.ComputeSignature(X509IncludeOption.EndCertOnly, root.GetAttribute("ID"), false);
            var signature = document.ImportNode(signer.GetXml(), true);
            root.InsertAfter(signature, root["Issuer", Saml2Constants.AssertionNamespaceX.NamespaceName]);

            // Enveloped signatures exclude their own ds:Object content from the digest.
            var signatureObject = document.CreateElement("ds", "Object", SignedXml.XmlDsigNamespaceUrl);
            signatureObject.AppendChild(login);
            signature.AppendChild(signatureObject);
            var verifier = new Saml2SignedXml(root, certificate,
                Saml2SecurityAlgorithms.RsaSha256Signature, SignedXml.XmlDsigExcC14NTransformUrl);
            verifier.LoadXml((System.Xml.XmlElement)signature);
            Assert.True(verifier.CheckSignature());

            var envelope = new XElement(Soap + "Envelope",
                new XElement(Soap + "Body", XElement.Parse(document.OuterXml, LoadOptions.PreserveWhitespace)));
            await Assert.ThrowsAsync<Saml2RequestException>(() => ResolveAsync(envelope, certificate));
        }

        [Fact]
        public void Read_UsesTheCurrentInnerResponseWhenInstanceIsReused()
        {
            var idp = new Saml2Configuration { Issuer = IdpIssuer };
            var first = new Saml2ArtifactResponse(idp, CreateLogin(idp)).ToXml();
            var second = new Saml2ArtifactResponse(idp, CreateLogin(idp)).ToXml();
            var secondSubject = (System.Xml.XmlElement)second.GetElementsByTagName("NameID", Saml2Constants.AssertionNamespaceX.NamespaceName)[0]!;
            secondSubject.InnerText = "second@example.test";
            var config = new Saml2Configuration { Issuer = SpIssuer };
            config.AllowedAudienceUris.Add(SpIssuer);
            var login = new Saml2AuthnResponse(config);
            var artifact = new ReadableArtifactResponse(config, login);

            artifact.ReadXml(first.OuterXml);
            Assert.Equal(Subject, login.NameId.Value);
            artifact.ReadXml(second.OuterXml);
            Assert.Equal("second@example.test", login.NameId.Value);
        }

        [Fact]
        public async Task ResolveAsync_RejectsUnsignedLoginWhenSigningCertificateIsConfigured()
        {
            using var certificate = CreateCertificate();
            var idp = new Saml2Configuration { Issuer = IdpIssuer };
            var artifact = new Saml2ArtifactResponse(idp, CreateLogin(idp));
            var envelope = XElement.Parse(new Saml2SoapEnvelope().Bind(artifact).SoapResponseXml);

            await Assert.ThrowsAsync<InvalidSignatureException>(() => ResolveAsync(envelope, certificate));
        }

        [Fact]
        public async Task ResolveAsync_RequiresSoapEnvelope()
        {
            var envelope = new XElement(Extension + "Envelope", new XElement(Soap + "Body"));

            await Assert.ThrowsAsync<Saml2RequestException>(() => ResolveAsync(envelope));
        }

        [Fact]
        public async Task ResolveAsync_ReadsSoapFaultFromBody()
        {
            var fault = new XElement(Soap + "Fault", new XElement("faultcode", "Server"), new XElement("faultstring", "Artifact unavailable"));
            var envelope = new XElement(Soap + "Envelope", new XElement(Soap + "Body", fault));

            var error = await Assert.ThrowsAsync<Saml2RequestException>(() => ResolveAsync(envelope));

            Assert.Contains("Artifact unavailable", error.Message);
        }

        private static Saml2AuthnResponse CreateLogin(Saml2Configuration config)
        {
            var response = new Saml2AuthnResponse(config)
            {
                Destination = new Uri(SpIssuer + "/acs"),
                ClaimsIdentity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, Subject),
                    new Claim(ClaimTypes.Email, Subject)
                })
            };
            response.CreateSecurityToken(SpIssuer);
            return response;
        }

        private static X509Certificate2 CreateCertificate()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=artifact-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

        private static async Task<Saml2ArtifactResponse> ResolveAsync(XElement envelope, X509Certificate2? certificate = null)
        {
            var config = new Saml2Configuration
            {
                Issuer = SpIssuer,
                AllowedIssuer = IdpIssuer,
                ArtifactResolutionService = new Saml2IndexedEndpoint { Location = new Uri(IdpIssuer + "/artifact") },
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };
            config.AllowedAudienceUris.Add(SpIssuer);
            if (certificate != null)
            {
                config.SignatureValidationCertificates.Add(certificate);
            }
            using var client = new HttpClient(new SoapResponseHandler(envelope));
            return await new Saml2SoapEnvelope().ResolveAsync(new ClientFactory(client),
                new Saml2ArtifactResolve(config) { Artifact = "test" }, new Saml2AuthnResponse(config));
        }

        private sealed class ClientFactory(HttpClient client) : IHttpClientFactory
        {
            public HttpClient CreateClient(string name) => client;
        }

        private sealed class ReadableArtifactResponse(Saml2Configuration config, Saml2Request request) : Saml2ArtifactResponse(config, request)
        {
            public void ReadXml(string xml) => Read(xml, false, false);
        }

        private sealed class SoapResponseHandler(XElement envelope) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(envelope.ToString(SaveOptions.DisableFormatting))
                });
            }
        }
    }
}
