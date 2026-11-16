using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tests.Bindings
{
    public partial class Saml2PostBindingSecurityTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsMultipleDirectSignatures(bool signAssertion)
        {
            using var signer = CreateCertificate();
            var document = CreateSignedResponse(signAssertion ? Saml2AuthnResponseSignTypes.SignAssertion : Saml2AuthnResponseSignTypes.SignResponse, signer);
            Assert.Equal(Subject, Unbind(document, signer).NameId.Value);
            var element = signAssertion ? document.DocumentElement!["Assertion", SamlNamespace]! : document.DocumentElement!;
            var signature = element["Signature", SignedXml.XmlDsigNamespaceUrl]!;
            element.AppendChild(signature.CloneNode(true));
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer));

            var exception = Assert.Throws<InvalidSignatureException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            Assert.Contains("more then one Signature", exception.Message);
            Assert.Null(response.ClaimsIdentity);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsMultipleCryptographicallyValidReferences(bool signAssertion)
        {
            using var signer = CreateCertificate();
            var document = CreateResponse();
            var element = signAssertion ? document.DocumentElement!["Assertion", SamlNamespace]! : document.DocumentElement!;
            SignForValidationTest(element, signer, "multiple");
            AssertSignatureValid(element, signer);
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer));

            var exception = Assert.Throws<InvalidSignatureException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            Assert.Contains("Invalid XML signature reference", exception.Message);
            Assert.Null(response.ClaimsIdentity);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsEmptyReference(bool signAssertion)
        {
            using var signer = CreateCertificate();
            var document = CreateResponse();
            var element = signAssertion ? document.DocumentElement!["Assertion", SamlNamespace]! : document.DocumentElement!;
            SignForValidationTest(element, signer, "empty");
            AssertSignatureValid(element, signer);
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer));

            var exception = Record.Exception(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            // Empty references can be valid XMLDSig but SAML requires the ID of the signed element.
            Assert.NotNull(exception);
            Assert.Null(response.ClaimsIdentity);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsExternalReferenceBeforeResolvingIt(bool signAssertion)
        {
            using var signer = CreateCertificate();
            var document = CreateSignedResponse(signAssertion ? Saml2AuthnResponseSignTypes.SignAssertion : Saml2AuthnResponseSignTypes.SignResponse, signer);
            var element = signAssertion ? document.DocumentElement!["Assertion", SamlNamespace]! : document.DocumentElement!;
            AssertSignatureValid(element, signer);
            var signature = element["Signature", SignedXml.XmlDsigNamespaceUrl]!;
            var reference = signature["SignedInfo", SignedXml.XmlDsigNamespaceUrl]!["Reference", SignedXml.XmlDsigNamespaceUrl]!;
            // Modify a previously local reference after signing; the fixture never resolves any URI.
            // Use a URN rather than a network address, including in the component under test.
            reference.SetAttribute("URI", "urn:test:external-signature-data");
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer));

            var exception = Assert.Throws<InvalidSignatureException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            Assert.Contains("reference do not refer to the root element", exception.Message);
            Assert.Null(response.ClaimsIdentity);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsCryptographicallyValidUnsupportedTransform(bool signAssertion)
        {
            using var signer = CreateCertificate();
            var document = CreateResponse();
            var element = signAssertion ? document.DocumentElement!["Assertion", SamlNamespace]! : document.DocumentElement!;
            SignForValidationTest(element, signer, "inclusive-transform");
            AssertSignatureValid(element, signer);
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer));

            var exception = Assert.Throws<InvalidSignatureException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            Assert.Contains("Illegal transform method", exception.Message);
            Assert.Null(response.ClaimsIdentity);
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse)]
        public void Unbind_RejectsSignatureWithoutConfiguredValidationCertificate(Saml2AuthnResponseSignTypes signType)
        {
            using var signer = CreateCertificate();
            var document = CreateSignedResponse(signType, signer);
            var config = CreateSpConfiguration(signer);
            config.SignatureValidationCertificates.Clear();
            var response = new Saml2AuthnResponse(config);

            Assert.Throws<InvalidSignatureException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            Assert.Null(response.ClaimsIdentity);
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse, true)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion, true)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, true)]
        public void Unbind_TriesMultipleSignatureValidationCertificates(Saml2AuthnResponseSignTypes signType, bool includeTrustedCertificate)
        {
            using var signer = CreateCertificate();
            using var oldSigner = CreateCertificate();
            using var unrelatedSigner = CreateCertificate();
            var document = CreateSignedResponse(signType, signer);
            var config = CreateSpConfiguration(oldSigner);
            config.SignatureValidationCertificates.Add(includeTrustedCertificate ? signer : unrelatedSigner);
            var response = new Saml2AuthnResponse(config);

            if (includeTrustedCertificate)
            {
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response);
                Assert.Equal(Subject, response.NameId.Value);
            }
            else
            {
                Assert.Throws<InvalidSignatureException>(() =>
                    new Saml2PostBinding().Unbind(CreatePostRequest(document), response));
                Assert.Null(response.ClaimsIdentity);
            }
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        public void Unbind_RejectsMutationOfInheritedSignedNamespace(bool encrypted, bool cloneAssertion)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            XmlElement namespaceOwner = document.DocumentElement;
            if (encrypted)
            {
                namespaceOwner = document.CreateElement("saml", "EncryptedAssertion", SamlNamespace);
                document.DocumentElement.ReplaceChild(namespaceOwner, assertion);
                namespaceOwner.AppendChild(assertion);
            }
            namespaceOwner.SetAttribute("xmlns:xs", "http://www.w3.org/2001/XMLSchema");
            Sign(assertion, signer, "xs");
            AssertSignatureValid(assertion, signer);
            if (encrypted)
            {
                EncryptAssertion(assertion, recipient);
            }
            Assert.Equal(Subject, Unbind(document, signer, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>()).NameId.Value);
            namespaceOwner.SetAttribute("xmlns:xs", "urn:test:changed-context");
            var config = CreateSpConfiguration(signer, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>());
            Saml2AuthnResponse response = cloneAssertion ? new CloningAuthnResponse(config) : new Saml2AuthnResponse(config);

            Assert.Throws<InvalidSignatureException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            Assert.Null(response.ClaimsIdentity);
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse, true)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion, true)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, true)]
        public void Unbind_AcceptsEcdsaSignatureWithSeparateRsaEncryptionCertificate(Saml2AuthnResponseSignTypes signType, bool encrypted)
        {
            using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var signer = new CertificateRequest("CN=local-ecdsa-audit", signingKey, HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            using var recipient = CreateCertificate();
            var idpConfig = new Saml2Configuration
            {
                Issuer = IdpIssuer,
                SigningCertificate = signer,
                SignatureAlgorithm = Saml2SecurityAlgorithms.EcdsaSha256Signature,
                EncryptionCertificate = encrypted ? recipient : null,
                AuthnResponseSignType = signType
            };
            var outgoing = new Saml2AuthnResponse(idpConfig)
            {
                Destination = new Uri(SpIssuer + "/acs"),
                Status = Saml2StatusCodes.Success,
                ClaimsIdentity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, Subject),
                    new Claim(ClaimTypes.Email, Subject)
                })
            };
            outgoing.CreateSecurityToken(SpIssuer);
            var document = new Saml2PostBinding().Bind(outgoing).XmlDocument;
            var responseSignature = document.DocumentElement!["Signature", SignedXml.XmlDsigNamespaceUrl];
            if (signType == Saml2AuthnResponseSignTypes.SignAssertion)
            {
                Assert.Null(responseSignature);
            }
            else
            {
                AssertEcdsaSignatureMethod(responseSignature);
            }
            var decryptedDocument = (XmlDocument)document.CloneNode(true);
            if (encrypted)
            {
                Assert.Null(decryptedDocument.DocumentElement!["Assertion", SamlNamespace]);
                using var decryptionKey = recipient.GetRSAPrivateKey()!;
                new Saml2EncryptedXml(decryptedDocument, decryptionKey).DecryptDocument();
            }
            var assertion = encrypted
                ? decryptedDocument.DocumentElement!["EncryptedAssertion", SamlNamespace]!["Assertion", SamlNamespace]!
                : decryptedDocument.DocumentElement!["Assertion", SamlNamespace]!;
            if (signType == Saml2AuthnResponseSignTypes.SignResponse)
            {
                Assert.Null(assertion["Signature", SignedXml.XmlDsigNamespaceUrl]);
            }
            else
            {
                AssertEcdsaSignatureMethod(assertion["Signature", SignedXml.XmlDsigNamespaceUrl]);
            }
            var spConfig = CreateSpConfiguration(signer, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>());
            spConfig.SignatureAlgorithm = Saml2SecurityAlgorithms.EcdsaSha256Signature;
            var response = new Saml2AuthnResponse(spConfig);

            new Saml2PostBinding().Unbind(CreatePostRequest(document), response);

            Assert.Equal(Subject, response.NameId.Value);
            Assert.Equal(Subject, response.ClaimsIdentity.FindFirst(ClaimTypes.Email)?.Value);
        }

        private static void AssertEcdsaSignatureMethod(XmlElement? signature)
        {
            Assert.NotNull(signature);
            Assert.Equal(Saml2SecurityAlgorithms.EcdsaSha256Signature,
                signature["SignedInfo", SignedXml.XmlDsigNamespaceUrl]!["SignatureMethod", SignedXml.XmlDsigNamespaceUrl]!.GetAttribute("Algorithm"));
        }

        private static void SignForValidationTest(XmlElement element, X509Certificate2 certificate, string referenceFormat)
        {
            using var key = certificate.GetRSAPrivateKey()!;
            var signedXml = new SignedXml(element) { SigningKey = key };
            signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
            for (var index = 0; index < (referenceFormat == "multiple" ? 2 : 1); index++)
            {
                var reference = new Reference(referenceFormat == "empty" ? "" : "#" + element.GetAttribute("ID"))
                {
                    DigestMethod = SignedXml.XmlDsigSHA256Url
                };
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(referenceFormat == "inclusive-transform" ? new XmlDsigC14NTransform() : new XmlDsigExcC14NTransform());
                signedXml.AddReference(reference);
            }
            signedXml.ComputeSignature();
            element.InsertAfter(element.OwnerDocument.ImportNode(signedXml.GetXml(), true), element["Issuer", SamlNamespace]);
        }

        private static void AssertSignatureValid(XmlElement element, X509Certificate2 certificate)
        {
            var verifier = new SignedXml(element);
            verifier.LoadXml(element["Signature", SignedXml.XmlDsigNamespaceUrl]!);
            Assert.True(verifier.CheckSignature(certificate, true));
        }
    }
}
