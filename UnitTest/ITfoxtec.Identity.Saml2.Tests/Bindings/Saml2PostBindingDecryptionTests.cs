using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tests.Bindings
{
    public partial class Saml2PostBindingSecurityTests
    {
        [Theory]
        [InlineData("wrong-namespace")]
        [InlineData("nested-assertion")]
        [InlineData("multiple-assertions")]
        [InlineData("text")]
        [InlineData("no-assertion")]
        public void Unbind_RejectsMalformedDecryptedAssertion(string structure)
        {
            using var signer = CreateCertificate();
            using var recipient = CreateCertificate();
            var document = CreateResponse();
            var assertion = document.DocumentElement!["Assertion", SamlNamespace]!;
            var assertionXml = assertion.OuterXml;

            // Prove that the same encryption fixture accepts a legitimate assertion.
            var control = (XmlDocument)document.CloneNode(true);
            EncryptAssertionPayload(control.DocumentElement!["Assertion", SamlNamespace]!, recipient, assertionXml);
            Sign(control.DocumentElement, signer);
            Assert.Equal(Subject, Unbind(control, signer, recipient).NameId.Value);

            var plaintext = structure switch
            {
                "wrong-namespace" => assertionXml.Replace(SamlNamespace, "urn:test:foreign"),
                "nested-assertion" => "<Wrapper>" + assertionXml + "</Wrapper>",
                "multiple-assertions" => assertionXml + assertionXml.Replace("_assertion", "_second"),
                "text" => "plain text",
                "no-assertion" => "<Wrapper />",
                _ => throw new ArgumentOutOfRangeException(nameof(structure))
            };
            EncryptAssertionPayload(assertion, recipient, plaintext);
            Sign(document.DocumentElement, signer);
            AssertSignatureValid(document.DocumentElement, signer);
            var response = new Saml2AuthnResponse(CreateSpConfiguration(signer, recipient));

            var exception = Assert.Throws<AggregateException>(() =>
                new Saml2PostBinding().Unbind(CreatePostRequest(document), response));

            // Require rejection of the decrypted structure, rather than a cryptographic failure.
            var innerException = Assert.IsType<Saml2RequestException>(Assert.Single(exception.InnerExceptions));
            Assert.Contains("There is not exactly one SAML Assertion element in the decrypted EncryptedAssertion", innerException.Message);
            Assert.Null(response.ClaimsIdentity);
        }

        private static void EncryptAssertionPayload(XmlElement assertion, X509Certificate2 certificate, string plaintext)
        {
            // Encrypt raw bytes to allow fragments and text that are not a single Assertion element.
            using var aes = Aes.Create();
            aes.KeySize = 256;
            using var publicKey = certificate.GetRSAPublicKey()!;
            var encryptedKey = new EncryptedKey
            {
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl),
                CipherData = new CipherData(publicKey.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA1))
            };
            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
                CipherData = new CipherData(new EncryptedXml().EncryptData(Encoding.UTF8.GetBytes(plaintext), aes))
            };
            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

            var document = assertion.OwnerDocument;
            var wrapper = document.CreateElement("saml", "EncryptedAssertion", SamlNamespace);
            assertion.ParentNode!.ReplaceChild(wrapper, assertion);
            wrapper.AppendChild(document.ImportNode(encryptedData.GetXml(), true));
        }
    }
}
