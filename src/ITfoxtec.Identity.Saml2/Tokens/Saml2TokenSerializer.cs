using ITfoxtec.Identity.Saml2.Cryptography;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tokens
{
    internal class Saml2TokenSerializer : Saml2Serializer
    {
        private readonly RSA encryptionPrivateKey;

        public Saml2TokenSerializer(RSA encryptionPrivateKey) : base() 
        {
            this.encryptionPrivateKey = encryptionPrivateKey;
        }

        protected override Saml2NameIdentifier ReadEncryptedId(XmlDictionaryReader reader)
        {
            var xmlDoc = new XmlDocument(reader.NameTable);
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(reader.ReadOuterXml());
            XmlElement decrypted = null;

            var enc = new Saml2EncryptedXml(xmlDoc, encryptionPrivateKey);
            enc.DecryptDocument();
            decrypted = xmlDoc.DocumentElement;

            reader = XmlDictionaryReader.CreateDictionaryReader(new XmlNodeReader(decrypted.FirstChild));
            return ReadNameIdentifier(reader, null);
        }
    }
}
