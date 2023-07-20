using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2EncryptedXml : EncryptedXml
    {
        public const string XmlEncKeyAlgorithmRSAOAEPUrl = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

        public RSA EncryptionPublicKey { get; set; }
        public RSA EncryptionPrivateKey { get; set; }

        public Saml2EncryptedXml(RSA encryptionPublicKey) : base()
        {
            EncryptionPublicKey = encryptionPublicKey;
        }

        public Saml2EncryptedXml(XmlDocument document) : base(document)
        {
            if (document == null) throw new ArgumentNullException(nameof(document));
        }

        public Saml2EncryptedXml(XmlDocument document, RSA encryptionPrivateKey) : this(document)
        {
            if (encryptionPrivateKey == null) throw new ArgumentNullException(nameof(encryptionPrivateKey));

            EncryptionPrivateKey = encryptionPrivateKey;
        }

        public virtual XmlElement EncryptAassertion(XmlElement assertionElement)
        {
            using (var encryptionAlgorithm = Aes.Create())
            {
                encryptionAlgorithm.KeySize = 256;

                var encryptedData = new EncryptedData
                {
                    Type = XmlEncElementUrl,
                    EncryptionMethod = new EncryptionMethod(XmlEncAES256Url),
                    KeyInfo = new KeyInfo()
                };
                encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(new EncryptedKey
                {
                    EncryptionMethod = new EncryptionMethod(XmlEncRSAOAEPUrl),
                    CipherData = new CipherData(EncryptKey(encryptionAlgorithm.Key, EncryptionPublicKey, true))
                }));

                var encryptedXml = new EncryptedXml();
                encryptedData.CipherData.CipherValue = encryptedXml.EncryptData(assertionElement, encryptionAlgorithm, false);

                return encryptedData.GetXml();
            }
        }

        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            if (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncKeyAlgorithmRSAOAEPUrl)
            {
                return EncryptionPrivateKey.Decrypt(encryptedKey.CipherData.CipherValue, GetEncryptionPadding(encryptedKey));
            }
            else
            {
                return DecryptKey(encryptedKey.CipherData.CipherValue, EncryptionPrivateKey, (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl));
            }
        }

        private static RSAEncryptionPadding GetEncryptionPadding(EncryptedKey encryptedKey)
        {
            var xmlElement = encryptedKey.GetXml();
            var nsm = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
            nsm.AddNamespace("enc", XmlEncNamespaceUrl);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            var digestMethodElement = xmlElement.SelectSingleNode("enc:EncryptionMethod/ds:DigestMethod", nsm) as XmlElement;
            if (digestMethodElement != null)
            {
                var method = digestMethodElement.GetAttribute("Algorithm");
                switch (method)
                {
                    case Saml2SecurityAlgorithms.Sha1Digest:
                        return RSAEncryptionPadding.OaepSHA1;
                    case Saml2SecurityAlgorithms.Sha256Digest:
                        return RSAEncryptionPadding.OaepSHA256;
                    case Saml2SecurityAlgorithms.Sha384Digest:
                        return RSAEncryptionPadding.OaepSHA384;
                    case Saml2SecurityAlgorithms.Sha512Digest:
                        return RSAEncryptionPadding.OaepSHA512;
                }
            }

            return RSAEncryptionPadding.OaepSHA256;
        }
    }
}
