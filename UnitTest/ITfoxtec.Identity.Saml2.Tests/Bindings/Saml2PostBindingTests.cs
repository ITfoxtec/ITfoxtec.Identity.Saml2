using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tests.Bindings
{
    public class Saml2PostBindingTests
    {
        private const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
        private const string IdpIssuer = "https://idp.example.test";
        private const string SpIssuer = "https://sp.example.test";
        private const string OriginalSubject = "legitimate@example.test";
        private const string InjectedSubject = "injected@example.test";

        [Theory]
        [InlineData(SpIssuer)]
        [InlineData("https://other-sp.example.test")]
        public void Unbind_RejectsUnsignedAssertionInsideResponseSignature_WhenNoDecryptionCertificateIsConfigured(string originalAudience)
        {
            using var signingCertificate = CreateCertificate("test-idp");
            using var encryptionCertificate = CreateCertificate("test-sp");
            var idpConfig = new Saml2Configuration
            {
                Issuer = IdpIssuer,
                SigningCertificate = signingCertificate,
                EncryptionCertificate = encryptionCertificate,
                AuthnResponseSignType = Saml2AuthnResponseSignTypes.SignResponse
            };
            var originalResponse = CreateResponse(idpConfig, originalAudience, OriginalSubject);
            var document = new Saml2PostBinding().Bind(originalResponse).XmlDocument;
            var spConfig = CreateSpConfiguration(signingCertificate);

            Assert.Empty(spConfig.DecryptionCertificates);
            Assert.NotNull(document.DocumentElement!["EncryptedAssertion", AssertionNamespace]);
            Assert.Null(document.DocumentElement["Assertion", AssertionNamespace]);

            // Without the injected assertion, this encrypted response cannot be consumed without a key.
            Assert.Throws<Saml2RequestException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), new Saml2AuthnResponse(spConfig)));

            var injectedResponse = CreateResponse(new Saml2Configuration { Issuer = IdpIssuer }, SpIssuer, InjectedSubject);
            var injectedAssertion = injectedResponse.ToXml().DocumentElement!["Assertion", AssertionNamespace]!;
            Assert.Null(injectedAssertion["Signature", SignedXml.XmlDsigNamespaceUrl]);

            // The enveloped-signature transform excludes ds:Signature and its descendants from the digest.
            // Add the unsigned assertion after signing, without changing the signed response content.
            var signature = document.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl]!;
            var signatureObject = document.CreateElement("ds", "Object", SignedXml.XmlDsigNamespaceUrl);
            signatureObject.AppendChild(document.ImportNode(injectedAssertion, true));
            signature.AppendChild(signatureObject);

            var receivedResponse = new Saml2AuthnResponse(spConfig);
            var exception = Record.Exception(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), receivedResponse));

            Assert.True(exception != null,
                $"Expected the unsigned assertion inside ds:Signature/ds:Object to be rejected, but Unbind accepted subject '{receivedResponse.NameId?.Value}'.");
            Assert.IsType<Saml2RequestException>(exception);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_AcceptsLegitimateResponseSignedAssertion(bool encryptAssertion)
        {
            using var signingCertificate = CreateCertificate("test-idp");
            using var encryptionCertificate = CreateCertificate("test-sp");
            var idpConfig = new Saml2Configuration
            {
                Issuer = IdpIssuer,
                SigningCertificate = signingCertificate,
                EncryptionCertificate = encryptAssertion ? encryptionCertificate : null,
                AuthnResponseSignType = Saml2AuthnResponseSignTypes.SignResponse
            };
            var document = new Saml2PostBinding().Bind(CreateResponse(idpConfig, SpIssuer, OriginalSubject)).XmlDocument;
            var spConfig = CreateSpConfiguration(signingCertificate);
            if (encryptAssertion)
            {
                spConfig.DecryptionCertificates.Add(encryptionCertificate);
            }
            var receivedResponse = new Saml2AuthnResponse(spConfig);

            new Saml2PostBinding().Unbind(CreatePostRequest(document), receivedResponse);

            Assert.Equal(OriginalSubject, receivedResponse.NameId.Value);
            Assert.Equal(OriginalSubject, receivedResponse.ClaimsIdentity.FindFirst(ClaimTypes.Email)?.Value);
        }

        private static Saml2AuthnResponse CreateResponse(Saml2Configuration config, string audience, string subject)
        {
            var response = new Saml2AuthnResponse(config)
            {
                Destination = new Uri(audience + "/acs"),
                Status = Saml2StatusCodes.Success,
                ClaimsIdentity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, subject),
                    new Claim(ClaimTypes.Email, subject)
                })
            };
            response.CreateSecurityToken(audience);
            return response;
        }

        private static Saml2Configuration CreateSpConfiguration(X509Certificate2 signingCertificate)
        {
            var config = new Saml2Configuration
            {
                Issuer = SpIssuer,
                AllowedIssuer = IdpIssuer,
                // Trust the self-signed test certificate; POST Unbind still validates the XML signature.
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };
            config.SignatureValidationCertificates.Add(signingCertificate);
            config.AllowedAudienceUris.Add(SpIssuer);
            return config;
        }

        private static HttpRequest CreatePostRequest(XmlDocument document)
        {
            return new HttpRequest
            {
                Method = "POST",
                Form = new NameValueCollection
                {
                    ["SAMLResponse"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(document.OuterXml))
                }
            };
        }

        private static X509Certificate2 CreateCertificate(string name)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }
    }
}
