using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Cryptography;
using Microsoft.IdentityModel.Tokens.Saml2;
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
        [InlineData(false, Saml2AuthnResponseSignTypes.SignResponse)]
        [InlineData(true, Saml2AuthnResponseSignTypes.SignResponse)]
        [InlineData(false, Saml2AuthnResponseSignTypes.SignAssertion)]
        [InlineData(true, Saml2AuthnResponseSignTypes.SignAssertion)]
        [InlineData(false, Saml2AuthnResponseSignTypes.SignAssertionAndResponse)]
        [InlineData(true, Saml2AuthnResponseSignTypes.SignAssertionAndResponse)]
        public void Unbind_AcceptsLegitimateSignedAssertion(bool encryptAssertion, Saml2AuthnResponseSignTypes signType)
        {
            using var signingCertificate = CreateCertificate("test-idp");
            using var encryptionCertificate = CreateCertificate("test-sp");
            var idpConfig = new Saml2Configuration
            {
                Issuer = IdpIssuer,
                SigningCertificate = signingCertificate,
                EncryptionCertificate = encryptAssertion ? encryptionCertificate : null,
                AuthnResponseSignType = signType
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

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_UsesLegitimateAssertion_WhenUnsignedAssertionIsInsideResponseSignature(bool encryptAssertion)
        {
            using var signingCertificate = CreateCertificate("test-idp");
            using var encryptionCertificate = CreateCertificate("test-sp");
            var idpConfig = new Saml2Configuration
            {
                Issuer = IdpIssuer,
                SigningCertificate = signingCertificate,
                EncryptionCertificate = encryptAssertion ? encryptionCertificate : null,
                AuthnResponseSignType = Saml2AuthnResponseSignTypes.SignAssertionAndResponse
            };
            var document = new Saml2PostBinding().Bind(CreateResponse(idpConfig, SpIssuer, OriginalSubject)).XmlDocument;
            var injectedResponse = CreateResponse(new Saml2Configuration { Issuer = IdpIssuer }, SpIssuer, InjectedSubject);
            var injectedAssertion = injectedResponse.ToXml().DocumentElement!["Assertion", AssertionNamespace]!;
            var signatureObject = document.CreateElement("ds", "Object", SignedXml.XmlDsigNamespaceUrl);
            signatureObject.AppendChild(document.ImportNode(injectedAssertion, true));
            document.DocumentElement!["Signature", SignedXml.XmlDsigNamespaceUrl]!.AppendChild(signatureObject);
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



        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_AcceptsAssertionWithNestedAdvice(bool encryptAssertion)
        {
            using var signingCertificate = CreateCertificate("test-idp");
            using var encryptionCertificate = CreateCertificate("test-sp");
            var idpConfig = new Saml2Configuration
            {
                Issuer = IdpIssuer,
                SigningCertificate = signingCertificate,
                EncryptionCertificate = encryptAssertion ? encryptionCertificate : null,
                AuthnResponseSignType = Saml2AuthnResponseSignTypes.SignAssertionAndResponse
            };
            var response = CreateResponse(idpConfig, SpIssuer, OriginalSubject);
            response.Saml2SecurityToken.Assertion.Advice = new Saml2Advice();
            response.Saml2SecurityToken.Assertion.Advice.Assertions.Add(
                CreateResponse(new Saml2Configuration { Issuer = IdpIssuer }, SpIssuer, "advice@example.test").Saml2SecurityToken.Assertion);
            var document = new Saml2PostBinding().Bind(response).XmlDocument;
            var spConfig = CreateSpConfiguration(signingCertificate);
            if (encryptAssertion)
            {
                spConfig.DecryptionCertificates.Add(encryptionCertificate);
            }
            var receivedResponse = new Saml2AuthnResponse(spConfig);

            new Saml2PostBinding().Unbind(CreatePostRequest(document), receivedResponse);

            Assert.Equal(OriginalSubject, receivedResponse.NameId.Value);
            Assert.Single(receivedResponse.Saml2SecurityToken.Assertion.Advice.Assertions);
        }

        [Theory]
        [InlineData("nested")]
        [InlineData("wrong-namespace")]
        [InlineData("duplicate")]
        public void Unbind_RejectsResponseWithoutExactlyOneDirectSamlAssertion(string structure)
        {
            using var signingCertificate = CreateCertificate("test-idp");
            var document = CreateResponse(new Saml2Configuration { Issuer = IdpIssuer }, SpIssuer, OriginalSubject).ToXml();
            var root = document.DocumentElement!;
            var assertion = root["Assertion", AssertionNamespace]!;
            switch (structure)
            {
                case "nested":
                    root.RemoveChild(assertion);
                    var wrapper = document.CreateElement("Wrapper", "urn:test:wrapper");
                    wrapper.AppendChild(assertion);
                    root.AppendChild(wrapper);
                    break;
                case "wrong-namespace":
                    var wrongNamespaceAssertion = document.CreateElement("other", "Assertion", "urn:test:other");
                    wrongNamespaceAssertion.InnerXml = assertion.InnerXml;
                    root.ReplaceChild(wrongNamespaceAssertion, assertion);
                    break;
                case "duplicate":
                    var duplicate = (XmlElement)assertion.CloneNode(true);
                    duplicate.SetAttribute("ID", "_duplicate");
                    root.AppendChild(duplicate);
                    break;
            }

            // Sign after changing the structure so rejection cannot be caused by a broken response signature.
            var signedXml = new Saml2SignedXml(root, signingCertificate,
                Saml2SecurityAlgorithms.RsaSha256Signature, SignedXml.XmlDsigExcC14NTransformUrl);
            signedXml.ComputeSignature(X509IncludeOption.EndCertOnly, root.GetAttribute("ID"), false);
            root.InsertAfter(document.ImportNode(signedXml.GetXml(), true), root["Issuer", AssertionNamespace]);

            Assert.Throws<Saml2RequestException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), new Saml2AuthnResponse(CreateSpConfiguration(signingCertificate))));
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
