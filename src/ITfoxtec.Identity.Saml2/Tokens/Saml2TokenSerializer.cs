#if !NETFULL
using ITfoxtec.Identity.Saml2.Cryptography;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tokens
{
    internal class Saml2TokenSerializer : Saml2Serializer
    {
        private readonly X509Certificate2 decryptionCertificate;

        public Saml2TokenSerializer(X509Certificate2 decryptionCertificate) : base() 
        {
            this.decryptionCertificate = decryptionCertificate;
        }

        protected override Saml2NameIdentifier ReadEncryptedId(XmlDictionaryReader reader)
        {
            var xmlDocument = reader.ReadOuterXml().ToXmlDocument();

            new Saml2EncryptedXml(xmlDocument, decryptionCertificate.GetSamlRSAPrivateKey()).DecryptDocument();

            var decryptedReader = XmlDictionaryReader.CreateDictionaryReader(new XmlNodeReader(xmlDocument.DocumentElement.FirstChild));
            return ReadNameIdentifier(decryptedReader, null);
        }
    }
}
#endif
