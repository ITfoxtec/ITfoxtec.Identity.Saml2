using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Security;
using System.Text;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Tests.Bindings
{
    public class Saml2AuthnRequestParsingTests
    {
        [Fact]
        public void ReadSamlRequest_ReadsOnlyDirectChildrenIncludingLegacyRequesterIdsInOrder()
        {
            var xml = """
                <p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:e="urn:test:extension"
                    ID="_request" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
                  <p:Extensions><e:Extra><a:AuthnContextClassRef>outside</a:AuthnContextClassRef><p:RequesterID>outside</p:RequesterID></e:Extra></p:Extensions>
                  <p:RequestedAuthnContext>
                    <a:AuthnContextClassRef> urn:test:first </a:AuthnContextClassRef>
                    <AuthnContextClassRef>unqualified</AuthnContextClassRef>
                    <e:Extra><a:AuthnContextClassRef>nested</a:AuthnContextClassRef></e:Extra>
                    <e:AuthnContextClassRef>foreign</e:AuthnContextClassRef>
                    <a:AuthnContextClassRef>urn:test:second</a:AuthnContextClassRef>
                  </p:RequestedAuthnContext>
                  <p:Scoping>
                    <p:RequesterID>urn:test:one</p:RequesterID>
                    <RequesterID> urn:test:legacy </RequesterID>
                    <e:RequesterID>foreign</e:RequesterID>
                    <e:Extra><RequesterID>nested</RequesterID><p:RequesterID>nested</p:RequesterID></e:Extra>
                    <p:RequesterID>urn:test:three</p:RequesterID>
                  </p:Scoping>
                </p:AuthnRequest>
                """;

            var request = ReadRequest(xml);

            Assert.Equal(new[] { "urn:test:first", "urn:test:second" }, request.RequestedAuthnContext.AuthnContextClassRef);
            Assert.Equal(new[] { "urn:test:one", "urn:test:legacy", "urn:test:three" }, request.Scoping.RequesterID);
        }

        [Fact]
        public void Unbind_IgnoresValuesInjectedInsideAValidRequestSignature()
        {
            using var key = RSA.Create(2048);
            using var certificate = new CertificateRequest("CN=request-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            var config = new Saml2Configuration
            {
                Issuer = "https://sp.example.test",
                SingleSignOnDestination = new Uri("https://idp.example.test/sso"),
                SigningCertificate = certificate,
                SignAuthnRequest = true,
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };
            config.SignatureValidationCertificates.Add(certificate);
            var request = new Saml2AuthnRequest(config)
            {
                RequestedAuthnContext = new RequestedAuthnContext { AuthnContextClassRef = new[] { "urn:test:expected-context" } },
                Scoping = new Scoping { RequesterID = new[] { "urn:test:expected-requester" } }
            };
            var document = new Saml2PostBinding().Bind(request).XmlDocument;
            var signature = document.DocumentElement!["Signature", SignedXml.XmlDsigNamespaceUrl]!;
            var injected = document.CreateElement("ds", "Object", SignedXml.XmlDsigNamespaceUrl);
            var context = document.CreateElement("a", "AuthnContextClassRef", Saml2Constants.AssertionNamespaceX.NamespaceName);
            context.InnerText = "urn:test:injected-context";
            var requester = document.CreateElement("p", "RequesterID", Saml2Constants.ProtocolNamespaceX.NamespaceName);
            requester.InnerText = "urn:test:injected-requester";
            injected.AppendChild(context);
            injected.AppendChild(requester);
            signature.AppendChild(injected);

            var received = new Saml2AuthnRequest(config);
            new Saml2PostBinding().Unbind(CreateHttpRequest(document.OuterXml), received);

            Assert.Equal(new[] { "urn:test:expected-context" }, received.RequestedAuthnContext.AuthnContextClassRef);
            Assert.Equal(new[] { "urn:test:expected-requester" }, received.Scoping.RequesterID);
        }

        [Fact]
        public void ToXml_WritesProtocolQualifiedRequesterIdsThatRoundTrip()
        {
            var request = new Saml2AuthnRequest(new Saml2Configuration())
            {
                Scoping = new Scoping { RequesterID = new[] { "urn:test:one", "urn:test:two" } }
            };
            var xml = request.ToXml().OuterXml;
            var protocol = Saml2Constants.ProtocolNamespaceX;
            var scoping = XElement.Parse(xml).Element(protocol + "Scoping")!;
            Assert.All(scoping.Elements(), e => Assert.Equal(protocol + "RequesterID", e.Name));
            Assert.Equal(request.Scoping.RequesterID, ReadRequest(xml).Scoping.RequesterID);
        }

        private static Saml2AuthnRequest ReadRequest(string xml)
        {
            return (Saml2AuthnRequest)new Saml2PostBinding().ReadSamlRequest(CreateHttpRequest(xml), new Saml2AuthnRequest(new Saml2Configuration()));
        }

        private static HttpRequest CreateHttpRequest(string xml)
        {
            return new HttpRequest
            {
                Method = "POST",
                Form = new NameValueCollection { ["SAMLRequest"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)) }
            };
        }
    }
}
