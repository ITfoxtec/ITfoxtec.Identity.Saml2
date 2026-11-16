using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Collections.Specialized;
using System.Globalization;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tests.Bindings
{
    // Build the XML, signatures and ciphertext independently of the library's response writer.
    public partial class Saml2PostBindingSecurityTests
    {
        private const string SamlNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
        private const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
        private const string IdpIssuer = "https://audit-idp.example.test";
        private const string SpIssuer = "https://audit-sp.example.test";
        private const string Subject = "legitimate@example.test";

        public static IEnumerable<object[]> SignatureFormats()
        {
            foreach (var signType in Enum.GetValues<Saml2AuthnResponseSignTypes>())
            {
                foreach (var encrypted in new[] { false, true })
                {
                    foreach (var prefix in new[] { "saml", "assertion", "" })
                    {
                        foreach (var withComments in new[] { false, true })
                        {
                            yield return new object[] { signType, encrypted, prefix, withComments };
                        }
                    }
                }
            }
        }

        public static IEnumerable<object[]> EncryptionFormats()
        {
            foreach (var signType in Enum.GetValues<Saml2AuthnResponseSignTypes>())
            {
                foreach (var algorithm in new[]
                {
                    Saml2EncryptionAlgorithms.XmlEncAES128Url,
                    Saml2EncryptionAlgorithms.XmlEncAES192Url,
                    Saml2EncryptionAlgorithms.XmlEncAES256Url,
                    Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl,
                    Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl,
                    Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl
                })
                {
                    foreach (var keyAlgorithm in new[]
                    {
                        Saml2EncryptionAlgorithms.XmlEncRSA15Url,
                        Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl,
                        Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url
                    })
                    {
                        yield return new object[] { signType, algorithm, keyAlgorithm };
                    }
                }
            }
        }

        [Theory]
        [MemberData(nameof(EncryptionFormats))]
        public void Unbind_AcceptsIndependentlyEncryptedAssertion(Saml2AuthnResponseSignTypes signType, string algorithm, string keyAlgorithm)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            if (signType != Saml2AuthnResponseSignTypes.SignResponse)
            {
                Sign(assertion, signer);
            }
            EncryptAssertion(assertion, recipient, algorithm, keyAlgorithm);
            if (signType != Saml2AuthnResponseSignTypes.SignAssertion)
            {
                Sign(document.DocumentElement, signer);
            }

            var response = Unbind(document, signer, recipient);

            Assert.Equal(Subject, response.NameId.Value);
            Assert.Equal(Subject, response.ClaimsIdentity.FindFirst(ClaimTypes.Email)?.Value);
        }

        [Theory]
        [MemberData(nameof(SignatureFormats))]
        public void Unbind_AcceptsIndependentlySignedResponse(Saml2AuthnResponseSignTypes signType, bool encrypted, string prefix, bool withComments)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateSignedResponse(signType, signer, encrypted ? recipient : null, prefix, withComments);

            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>()));
            if (withComments)
            {
                response.Config.XmlCanonicalizationMethod = SignedXml.XmlDsigExcC14NWithCommentsTransformUrl;
            }
            new Saml2PostBinding().Unbind(CreatePostRequest(document), response);

            Assert.Equal(Subject, response.NameId.Value);
            Assert.Equal(Subject, response.ClaimsIdentity.FindFirst(ClaimTypes.Email)?.Value);
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse, true)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion, true)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, false)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, true)]
        public void Unbind_RejectsUntrustedSigningKey(Saml2AuthnResponseSignTypes signType, bool encrypted)
        {
            using var trustedSigner = CreateCertificate();
            using var untrustedSigner = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateSignedResponse(signType, untrustedSigner, encrypted ? recipient : null);

            Assert.Throws<InvalidSignatureException>(() =>
                Unbind(document, trustedSigner, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>()));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsUnsignedResponseAndAssertion(bool encrypted)
        {
            using var trustedSigner = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            if (encrypted)
            {
                EncryptAssertion(document.DocumentElement!["Assertion", SamlNamespace]!, recipient);
            }

            Assert.Throws<InvalidSignatureException>(() =>
                Unbind(document, trustedSigner, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>()));
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse)]
        public void Unbind_RejectsTamperedSubject(Saml2AuthnResponseSignTypes signType)
        {
            using var signer = CreateCertificate();
            var document = CreateSignedResponse(signType, signer);
            document.DocumentElement!["Assertion", SamlNamespace]!["Subject", SamlNamespace]!["NameID", SamlNamespace]!.InnerText = "injected@example.test";

            Assert.Throws<InvalidSignatureException>(() => Unbind(document, signer));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsInvalidResponseSignatureDespiteValidAssertionSignature(bool encrypted)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateSignedResponse(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, signer, encrypted ? recipient : null);
            document.DocumentElement!.SetAttribute("Destination", "https://changed.example.test/acs");

            Assert.Throws<InvalidSignatureException>(() =>
                Unbind(document, signer, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>()));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsInvalidAssertionSignatureDespiteValidResponseSignature(bool encrypted)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            Sign(assertion, signer);
            assertion["Subject", SamlNamespace]!["NameID", SamlNamespace]!.InnerText = "injected@example.test";
            if (encrypted)
            {
                EncryptAssertion(assertion, recipient);
            }
            Sign(document.DocumentElement!, signer);

            Assert.Throws<InvalidSignatureException>(() =>
                Unbind(document, signer, encrypted ? new[] { recipient } : Array.Empty<X509Certificate2>()));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_DoesNotPromoteEncryptedAssertionInsideSignature(bool includeLegitimateAssertion)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            if (includeLegitimateAssertion)
            {
                EncryptAssertion(assertion, recipient);
            }
            else
            {
                document.DocumentElement.RemoveChild(assertion);
            }
            Sign(document.DocumentElement, signer);

            var injectedDocument = CreateResponse("injected@example.test");
            EncryptAssertion(injectedDocument.DocumentElement!["Assertion", SamlNamespace]!, recipient);
            var signatureObject = document.CreateElement("ds", "Object", SignedXml.XmlDsigNamespaceUrl);
            signatureObject.AppendChild(document.ImportNode(injectedDocument.DocumentElement["EncryptedAssertion", SamlNamespace]!, true));
            document.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl]!.AppendChild(signatureObject);

            if (includeLegitimateAssertion)
            {
                Assert.Equal(Subject, Unbind(document, signer, recipient).NameId.Value);
            }
            else
            {
                Assert.Throws<Saml2RequestException>(() => Unbind(document, signer, recipient));
            }
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        public void Unbind_PreservesSignedNamespaceContextAfterDecryption(bool signResponse, bool cloneAssertion)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            var wrapper = document.CreateElement("saml", "EncryptedAssertion", SamlNamespace);
            wrapper.SetAttribute("xmlns:xs", "http://www.w3.org/2001/XMLSchema");
            document.DocumentElement.ReplaceChild(wrapper, assertion);
            wrapper.AppendChild(assertion);
            Sign(assertion, signer, "xs");
            EncryptAssertion(assertion, recipient);
            if (signResponse)
            {
                Sign(document.DocumentElement, signer);
            }

            // Independent control: the decrypted assertion's signature is valid in its original context.
            var decrypted = (XmlDocument)document.CloneNode(true);
            var decryptor = new EncryptedXml(decrypted);
            using var privateKey = recipient.GetRSAPrivateKey()!;
            decryptor.AddKeyNameMapping("audit-encryption-key", privateKey);
            decryptor.DecryptDocument();
            var decryptedAssertion = decrypted.DocumentElement!["EncryptedAssertion", SamlNamespace]!["Assertion", SamlNamespace]!;
            var verifier = new SignedXml(decryptedAssertion);
            verifier.LoadXml(decryptedAssertion["Signature", SignedXml.XmlDsigNamespaceUrl]!);
            Assert.True(verifier.CheckSignature(signer, true));

            Saml2AuthnResponse response = cloneAssertion ? new CloningAuthnResponse(CreateSpConfiguration(signer, recipient)) :
                new Saml2AuthnResponse(CreateSpConfiguration(signer, recipient));
            new Saml2PostBinding().Unbind(CreatePostRequest(document), response);
            Assert.Equal(Subject, response.NameId.Value);
        }

        [Fact]
        public void Unbind_TriesNextDecryptionCertificate()
        {
            using var signer = CreateCertificate();
            using var incorrectRecipient = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateSignedResponse(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, signer, recipient);

            Assert.Equal(Subject, Unbind(document, signer, incorrectRecipient, recipient).NameId.Value);
            Assert.Throws<AggregateException>(() => Unbind(document, signer, incorrectRecipient));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsMultipleAssertionsAfterDecryption(bool mixPlainAndEncrypted)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            var second = (XmlElement)assertion.CloneNode(true);
            second.SetAttribute("ID", "_second");
            document.DocumentElement.AppendChild(second);
            EncryptAssertion(assertion, recipient);
            if (!mixPlainAndEncrypted)
            {
                EncryptAssertion(second, recipient);
            }
            Sign(document.DocumentElement, signer);

            Assert.Throws<Saml2RequestException>(() => Unbind(document, signer, recipient));
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public void Unbind_DoesNotReuseAssertionFromAnEarlierRead(bool firstEncrypted, bool validateFirst)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var firstDocument = CreateResponse("earlier@example.test");
            if (firstEncrypted)
            {
                EncryptAssertion(firstDocument.DocumentElement!["Assertion", SamlNamespace]!, recipient);
            }
            Sign(firstDocument.DocumentElement!, signer);
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer, recipient));
            var binding = new Saml2PostBinding();
            if (validateFirst)
            {
                binding.Unbind(CreatePostRequest(firstDocument), response);
            }
            else
            {
                binding.ReadSamlResponse(CreatePostRequest(firstDocument), response);
            }
            Assert.Equal("earlier@example.test", response.NameId.Value);

            var currentDocument = CreateSignedResponse(Saml2AuthnResponseSignTypes.SignResponse, signer);
            binding.Unbind(CreatePostRequest(currentDocument), response);

            Assert.Equal(Subject, response.NameId.Value);
            Assert.Equal(Subject, response.ClaimsIdentity.FindFirst(ClaimTypes.Email)?.Value);
        }

        [Fact]
        public void Unbind_DoesNotReusePreviouslyDecryptedAssertionForResponseWithoutAssertion()
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var response = Unbind(CreateSignedResponse(Saml2AuthnResponseSignTypes.SignResponse, signer, recipient), signer, recipient);
            var document = CreateResponse();
            document.DocumentElement!.RemoveChild(document.DocumentElement["Assertion", SamlNamespace]!);
            Sign(document.DocumentElement, signer);

            Assert.Throws<Saml2RequestException>(() => new Saml2PostBinding().Unbind(CreatePostRequest(document), response));
        }

        [Theory]
        [InlineData("empty")]
        [InlineData("plaintext")]
        [InlineData("mixed")]
        [InlineData("duplicate-ciphertext")]
        public void Unbind_RejectsMalformedEncryptedAssertion(string structure)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            var plaintext = assertion.CloneNode(true);
            EncryptAssertion(assertion, recipient);
            var wrapper = document.DocumentElement["EncryptedAssertion", SamlNamespace]!;
            if (structure == "empty" || structure == "plaintext")
            {
                wrapper.RemoveAll();
            }
            if (structure == "plaintext" || structure == "mixed")
            {
                wrapper.AppendChild(plaintext);
            }
            if (structure == "duplicate-ciphertext")
            {
                wrapper.AppendChild(wrapper.FirstChild!.CloneNode(true));
            }
            Sign(document.DocumentElement, signer);

            Assert.Throws<Saml2RequestException>(() => Unbind(document, signer, recipient));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsAssertionInSignedForeignWrapper(bool encrypted)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            var wrapper = document.CreateElement("foreign", "EncryptedAssertion", "urn:test:foreign");
            document.DocumentElement.ReplaceChild(wrapper, assertion);
            wrapper.AppendChild(assertion);
            if (encrypted)
            {
                // A correctly encrypted SAML container is still inadmissible when nested in a foreign wrapper.
                EncryptAssertion(assertion, recipient);
            }
            Sign(document.DocumentElement, signer);

            Assert.Throws<Saml2RequestException>(() => Unbind(document, signer, recipient));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_RejectsSignatureReferenceToAnotherElement(bool signAssertion)
        {
            using var signer = CreateCertificate();
            var document = CreateResponse();
            var target = signAssertion ? document.DocumentElement!["Assertion", SamlNamespace]! : document.DocumentElement!;
            var decoy = document.CreateElement("Decoy", "urn:test:decoy");
            decoy.SetAttribute("ID", "_decoy");
            document.DocumentElement!.AppendChild(decoy);
            Sign(target, signer, referenceId: "_decoy");

            Assert.Throws<InvalidSignatureException>(() => Unbind(document, signer));
        }

        [Fact]
        public void Unbind_RejectsDuplicateAssertionId()
        {
            using var signer = CreateCertificate();
            var document = CreateSignedResponse(Saml2AuthnResponseSignTypes.SignAssertion, signer);
            var decoy = document.CreateElement("Decoy", "urn:test:decoy");
            decoy.SetAttribute("ID", "_assertion");
            document.DocumentElement!.AppendChild(decoy);

            Assert.ThrowsAny<CryptographicException>(() => Unbind(document, signer));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Unbind_IgnoresCommentsExcludedByShortIdReference(bool withComments)
        {
            using var signer = CreateCertificate();
            var document = CreateResponse();
            var comment = document.CreateComment("original signed comment");
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            assertion.AppendChild(comment);
            Sign(assertion, signer, withComments: withComments);
            var config = CreateSpConfiguration(signer);
            config.XmlCanonicalizationMethod = withComments ? SignedXml.XmlDsigExcC14NWithCommentsTransformUrl : SignedXml.XmlDsigExcC14NTransformUrl;
            new Saml2PostBinding().Unbind(CreatePostRequest(document), new Saml2AuthnResponse(config));
            comment.Value = "changed after signing";
            var response = new Saml2AuthnResponse(config);

            // A short #ID reference removes comments before canonicalization, even with WithComments.
            AssertSignatureValid(assertion, signer);
            new Saml2PostBinding().Unbind(CreatePostRequest(document), response);
            Assert.Equal(Subject, response.NameId.Value);
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse)]
        public void Unbind_RejectsCiphertextTamperedAfterResponseSigning(Saml2AuthnResponseSignTypes signType)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateSignedResponse(signType, signer, recipient);
            Assert.Equal(Subject, Unbind(document, signer, recipient).NameId.Value);
            var encryptedData = document.DocumentElement!["EncryptedAssertion", SamlNamespace]!["EncryptedData", EncryptedXml.XmlEncNamespaceUrl]!;
            var cipherValue = encryptedData["CipherData", EncryptedXml.XmlEncNamespaceUrl]!["CipherValue", EncryptedXml.XmlEncNamespaceUrl]!;
            var bytes = Convert.FromBase64String(cipherValue.InnerText);
            bytes[0] ^= 1;
            cipherValue.InnerText = Convert.ToBase64String(bytes);

            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer, recipient));
            var exception = Record.Exception(() => new Saml2PostBinding().Unbind(CreatePostRequest(document), response));
            Assert.True(exception is InvalidSignatureException || exception is AggregateException,
                $"Expected signature or decryption rejection, got {exception?.GetType().Name ?? "no exception"}.");
            Assert.Null(response.ClaimsIdentity);
        }

        [Fact]
        public void Unbind_RejectsInvalidGcmAuthenticationTag()
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            Sign(assertion, signer);
            EncryptAssertion(assertion, recipient, Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl);
            Assert.Equal(Subject, Unbind(document, signer, recipient).NameId.Value);
            var encryptedData = document.DocumentElement["EncryptedAssertion", SamlNamespace]!["EncryptedData", EncryptedXml.XmlEncNamespaceUrl]!;
            var cipherValue = encryptedData["CipherData", EncryptedXml.XmlEncNamespaceUrl]!["CipherValue", EncryptedXml.XmlEncNamespaceUrl]!;
            var bytes = Convert.FromBase64String(cipherValue.InnerText);
            bytes[bytes.Length - 1] ^= 1;
            cipherValue.InnerText = Convert.ToBase64String(bytes);

            var exception = Assert.Throws<AggregateException>(() => Unbind(document, signer, recipient));
            Assert.IsAssignableFrom<CryptographicException>(Assert.Single(exception.InnerExceptions));
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse)]
        public void Bind_CanReuseResponseAfterEncryptedUnbind(Saml2AuthnResponseSignTypes signType)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var response = Unbind(CreateSignedResponse(Saml2AuthnResponseSignTypes.SignAssertionAndResponse, signer, recipient), signer, recipient);
            response.Config.SigningCertificate = signer;
            response.Config.AuthnResponseSignType = signType;

            var rebound = new Saml2PostBinding().Bind(response).XmlDocument;

            Assert.Equal(Subject, Unbind(rebound, signer).NameId.Value);
        }

        [Theory]
        [InlineData(Saml2AuthnResponseSignTypes.SignResponse)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertion)]
        [InlineData(Saml2AuthnResponseSignTypes.SignAssertionAndResponse)]
        public void Unbind_RejectsBareEncryptedDataWithoutSamlContainer(Saml2AuthnResponseSignTypes signType)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateSignedResponse(signType, signer, recipient);
            var wrapper = document.DocumentElement!["EncryptedAssertion", SamlNamespace]!;
            var encryptedData = wrapper["EncryptedData", EncryptedXml.XmlEncNamespaceUrl]!;
            wrapper.RemoveChild(encryptedData);
            document.DocumentElement.ReplaceChild(encryptedData, wrapper);
            var responseSignature = document.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];
            if (responseSignature != null)
            {
                document.DocumentElement.RemoveChild(responseSignature);
                Sign(document.DocumentElement, signer);
            }

            Assert.Throws<Saml2RequestException>(() => Unbind(document, signer, recipient));
        }

        [Theory]
        [InlineData("object", false)]
        [InlineData("object", true)]
        [InlineData("key-info", false)]
        [InlineData("key-info", true)]
        [InlineData("signature-property", false)]
        [InlineData("signature-property", true)]
        [InlineData("foreign-wrapper", false)]
        [InlineData("foreign-wrapper", true)]
        [InlineData("nested-encrypted-container", false)]
        [InlineData("nested-encrypted-container", true)]
        public void Unbind_NeverConsumesUnsignedAssertionInsertedInsideSignature(string placement, bool hasDecryptionKey)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateSignedResponse(Saml2AuthnResponseSignTypes.SignResponse, signer, recipient);
            var injected = CreateResponse("injected@example.test").DocumentElement!["Assertion", SamlNamespace]!;
            injected.SetAttribute("ID", "_injected");
            var signature = document.DocumentElement!["Signature", SignedXml.XmlDsigNamespaceUrl]!;
            XmlElement container;
            if (placement == "key-info")
            {
                container = signature["KeyInfo", SignedXml.XmlDsigNamespaceUrl]!;
            }
            else
            {
                container = document.CreateElement("ds", "Object", SignedXml.XmlDsigNamespaceUrl);
                signature.AppendChild(container);
                if (placement != "object")
                {
                    var inner = placement switch
                    {
                        "signature-property" => document.CreateElement("ds", "SignatureProperty", SignedXml.XmlDsigNamespaceUrl),
                        "nested-encrypted-container" => document.CreateElement("saml", "EncryptedAssertion", SamlNamespace),
                        _ => document.CreateElement("foreign", "Assertion", "urn:test:foreign")
                    };
                    container.AppendChild(inner);
                    container = inner;
                }
            }
            container.AppendChild(document.ImportNode(injected, true));
            // The attack leaves the original response signature valid, independently checked here.
            AssertSignatureValid(document.DocumentElement, signer);
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer, hasDecryptionKey ? new[] { recipient } : Array.Empty<X509Certificate2>()));

            if (hasDecryptionKey)
            {
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response);
                Assert.Equal(Subject, response.NameId.Value);
                Assert.Equal(Subject, response.ClaimsIdentity.FindFirst(ClaimTypes.Email)?.Value);
            }
            else
            {
                Assert.Throws<Saml2RequestException>(() => new Saml2PostBinding().Unbind(CreatePostRequest(document), response));
                Assert.Null(response.ClaimsIdentity);
            }
        }

        private sealed class CloningAuthnResponse : Saml2AuthnResponse
        {
            public CloningAuthnResponse(Saml2Configuration config) : base(config)
            { }

            protected override XmlElement GetAssertionElement()
            {
                // Exercise the namespace-preserving copy used by the older framework branches.
                var assertion = base.GetAssertionElement();
                var copyMethod = typeof(Saml2AuthnResponse).Assembly.GetType("ITfoxtec.Identity.Saml2.XmlElementExtensions")!
                    .GetMethod("ToXmlDocument", BindingFlags.Static | BindingFlags.NonPublic)!;
                var copy = (XmlDocument)copyMethod.Invoke(null, new object[] { assertion })!;
                return copy.DocumentElement!;
            }
        }

        private static XmlDocument CreateResponse(string subject = Subject, string prefix = "saml")
        {
            var now = DateTime.UtcNow;
            var issued = now.ToString("o", CultureInfo.InvariantCulture);
            var expires = now.AddMinutes(10).ToString("o", CultureInfo.InvariantCulture);
            var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            var xml = $"""
                <samlp:Response xmlns:samlp="{ProtocolNamespace}" ID="_response" Version="2.0" IssueInstant="{issued}" Destination="{SpIssuer}/acs">
                  <saml:Issuer xmlns:saml="{SamlNamespace}">{IdpIssuer}</saml:Issuer>
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>
                  <saml:Assertion xmlns:saml="{SamlNamespace}" ID="_assertion" Version="2.0" IssueInstant="{issued}">
                    <saml:Issuer>{IdpIssuer}</saml:Issuer>
                    <saml:Subject>
                      <saml:NameID>{subject}</saml:NameID>
                      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                        <saml:SubjectConfirmationData NotOnOrAfter="{expires}" Recipient="{SpIssuer}/acs" />
                      </saml:SubjectConfirmation>
                    </saml:Subject>
                    <saml:Conditions NotOnOrAfter="{expires}">
                      <saml:AudienceRestriction><saml:Audience>{SpIssuer}</saml:Audience></saml:AudienceRestriction>
                    </saml:Conditions>
                    <saml:AuthnStatement AuthnInstant="{issued}">
                      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
                    </saml:AuthnStatement>
                    <saml:AttributeStatement>
                      <saml:Attribute Name="{ClaimTypes.Email}"><saml:AttributeValue>{subject}</saml:AttributeValue></saml:Attribute>
                    </saml:AttributeStatement>
                  </saml:Assertion>
                </samlp:Response>
                """;
            xml = xml.Replace("xmlns:saml=", prefix.Length == 0 ? "xmlns=" : $"xmlns:{prefix}=")
                .Replace("saml:", prefix.Length == 0 ? "" : prefix + ":");
            document.LoadXml(xml);
            return document;
        }

        private static XmlDocument CreateSignedResponse(Saml2AuthnResponseSignTypes signType, X509Certificate2 signer, X509Certificate2? recipient = null, string prefix = "saml", bool withComments = false)
        {
            var document = CreateResponse(prefix: prefix);
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            if (signType != Saml2AuthnResponseSignTypes.SignResponse)
            {
                Sign(assertion, signer, withComments: withComments);
            }
            if (recipient != null)
            {
                EncryptAssertion(assertion, recipient);
            }
            if (signType != Saml2AuthnResponseSignTypes.SignAssertion)
            {
                Sign(document.DocumentElement, signer, withComments: withComments);
            }
            return document;
        }

        private static void Sign(XmlElement element, X509Certificate2 certificate, string? inclusivePrefixes = null, bool withComments = false, string? referenceId = null)
        {
            using var key = certificate.GetRSAPrivateKey()!;
            var signedXml = new SignedXml(element) { SigningKey = key };
            signedXml.SignedInfo!.CanonicalizationMethod = withComments ? SignedXml.XmlDsigExcC14NWithCommentsTransformUrl : SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
            var reference = new Reference("#" + (referenceId ?? element.GetAttribute("ID"))) { DigestMethod = SignedXml.XmlDsigSHA256Url };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform(withComments) { InclusiveNamespacesPrefixList = inclusivePrefixes });
            signedXml.AddReference(reference);
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certificate));
            signedXml.ComputeSignature();
            element.InsertAfter(element.OwnerDocument.ImportNode(signedXml.GetXml(), true), element["Issuer", SamlNamespace]);
        }

        private static void EncryptAssertion(XmlElement assertion, X509Certificate2 certificate,
            string algorithm = EncryptedXml.XmlEncAES256Url, string keyAlgorithm = EncryptedXml.XmlEncRSAOAEPUrl)
        {
            using var aes = Aes.Create();
            aes.KeySize = algorithm.Contains("128", StringComparison.Ordinal) ? 128 : algorithm.Contains("192", StringComparison.Ordinal) ? 192 : 256;
            using var publicKey = certificate.GetRSAPublicKey()!;
            var padding = keyAlgorithm == Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url ? RSAEncryptionPadding.OaepSHA256 :
                keyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl ? RSAEncryptionPadding.OaepSHA1 : RSAEncryptionPadding.Pkcs1;
            var encryptedKey = new EncryptedKey
            {
                EncryptionMethod = new EncryptionMethod(keyAlgorithm),
                CipherData = new CipherData(publicKey.Encrypt(aes.Key, padding))
            };
            encryptedKey.KeyInfo.AddClause(new KeyInfoName("audit-encryption-key"));
            byte[] ciphertext;
            if (algorithm.EndsWith("-gcm", StringComparison.Ordinal))
            {
                var plaintext = Encoding.UTF8.GetBytes(assertion.OuterXml);
                var nonce = RandomNumberGenerator.GetBytes(12);
                var encrypted = new byte[plaintext.Length];
                var tag = new byte[16];
                using var gcm = new AesGcm(aes.Key, tag.Length);
                gcm.Encrypt(nonce, plaintext, encrypted, tag);
                ciphertext = nonce.Concat(encrypted).Concat(tag).ToArray();
            }
            else
            {
                ciphertext = new EncryptedXml().EncryptData(assertion, aes, false);
            }
            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(algorithm),
                CipherData = new CipherData(ciphertext)
            };
            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
            var encryptedDataElement = encryptedData.GetXml();
            if (keyAlgorithm == Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url)
            {
                var method = (XmlElement)encryptedDataElement.GetElementsByTagName("EncryptionMethod", EncryptedXml.XmlEncNamespaceUrl)[1]!;
                var digest = encryptedDataElement.OwnerDocument.CreateElement("ds", "DigestMethod", SignedXml.XmlDsigNamespaceUrl);
                digest.SetAttribute("Algorithm", SignedXml.XmlDsigSHA256Url);
                method.AppendChild(digest);
                var mgf = encryptedDataElement.OwnerDocument.CreateElement("xenc11", "MGF", "http://www.w3.org/2009/xmlenc11#");
                mgf.SetAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha256");
                method.AppendChild(mgf);
            }
            var wrapper = assertion.ParentNode as XmlElement;
            if (wrapper!.LocalName != "EncryptedAssertion" || wrapper.NamespaceURI != SamlNamespace)
            {
                wrapper = assertion.OwnerDocument.CreateElement("saml", "EncryptedAssertion", SamlNamespace);
                assertion.ParentNode!.ReplaceChild(wrapper, assertion);
            }
            else
            {
                wrapper.RemoveChild(assertion);
            }
            wrapper.AppendChild(assertion.OwnerDocument.ImportNode(encryptedDataElement, true));
        }

        private static Saml2AuthnResponse Unbind(XmlDocument document, X509Certificate2 signer, params X509Certificate2[] recipients)
        {
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer, recipients));
            new Saml2PostBinding().Unbind(CreatePostRequest(document), response);
            return response;
        }

        private static Saml2Configuration CreateSpConfiguration(X509Certificate2 signer, params X509Certificate2[] recipients)
        {
            var config = new Saml2Configuration
            {
                Issuer = SpIssuer,
                AllowedIssuer = IdpIssuer,
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };
            config.SignatureValidationCertificates.Add(signer);
            config.AllowedAudienceUris.Add(SpIssuer);
            config.DecryptionCertificates.AddRange(recipients);
            return config;
        }

        private static HttpRequest CreatePostRequest(XmlDocument document)
        {
            return new HttpRequest
            {
                Method = "POST",
                Form = new NameValueCollection { ["SAMLResponse"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(document.OuterXml)) }
            };
        }

        private static X509Certificate2 CreateCertificate()
        {
            using var key = RSA.Create(2048);
            return new CertificateRequest("CN=local-audit", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }
    }
}
