#if !NETFULL
using ITfoxtec.Identity.Saml2.Cryptography;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Collections.Generic;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Linq;

namespace ITfoxtec.Identity.Saml2.Tokens
{
    internal class Saml2TokenSerializer : Saml2Serializer
    {
        private readonly X509Certificate2[] decryptionCertificates;

        public Saml2TokenSerializer(X509Certificate2[] decryptionCertificate) : base() 
        {
            this.decryptionCertificates = decryptionCertificate;
        }

        protected override Saml2NameIdentifier ReadEncryptedId(XmlDictionaryReader reader)
        {
            var xmlDocument = reader.ReadOuterXml().ToXmlDocument();

            List<Exception> exceptions = new List<Exception>(decryptionCertificates.Length);

            for(int i = 0; i < decryptionCertificates.Length; i++)
            {
                X509Certificate2 certificate = decryptionCertificates[i];
                try
                {
                    new Saml2EncryptedXml(xmlDocument, certificate.GetSamlRSAPrivateKey()).DecryptDocument();
                    // This is abit of a hack to stop the flow if we decrypt the message on the first try.
                    break;
                }
                catch(Exception e)
                {
                    exceptions[i] = e;
                }
            }

            if(exceptions.Count() == decryptionCertificates.Length)
            {
                throw new AggregateException("Failed to decrypt message", exceptions);
            }

            var decryptedReader = XmlDictionaryReader.CreateDictionaryReader(new XmlNodeReader(xmlDocument.DocumentElement.FirstChild));
            return ReadNameIdentifier(decryptedReader, null);
        }
    }
}
#endif
