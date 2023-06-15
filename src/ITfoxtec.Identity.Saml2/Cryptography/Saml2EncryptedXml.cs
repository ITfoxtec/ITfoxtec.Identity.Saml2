using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2EncryptedXml : EncryptedXml
    {
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
            using (var encryptionAlgorithm = new AesCryptoServiceProvider())
            {
                encryptionAlgorithm.KeySize = 256;

                var encryptedData = new EncryptedData
                {
                    Type = EncryptedXml.XmlEncElementUrl,
                    EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
                    KeyInfo = new KeyInfo()
                };
                encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(new EncryptedKey
                {
                    EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl),
                    CipherData = new CipherData(EncryptedXml.EncryptKey(encryptionAlgorithm.Key, EncryptionPublicKey, true))
                }));

                var encryptedXml = new EncryptedXml();
                encryptedData.CipherData.CipherValue = encryptedXml.EncryptData(assertionElement, encryptionAlgorithm, false);

                return encryptedData.GetXml();
            }
        }

        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            string rsaoaep = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

            byte[] key;
            if (encryptedKey.EncryptionMethod.KeyAlgorithm == rsaoaep)
            {
                // check if we have an explicit digest method, default to SHA1
                var padding = RSAEncryptionPadding.OaepSHA1;

                var xml = encryptedKey.GetXml();
                XmlNamespaceManager nsm = new XmlNamespaceManager(xml.OwnerDocument.NameTable);
                nsm.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);
                nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                var digestMethodElement = xml.SelectSingleNode("enc:EncryptionMethod/ds:DigestMethod", nsm) as XmlElement;
                if (digestMethodElement != null)
                {
                    var method = digestMethodElement.GetAttribute("Algorithm");
                    switch (method)
                    {
                        case Saml2SecurityAlgorithms.Sha1Digest:
                            padding = RSAEncryptionPadding.OaepSHA1;
                            break;
                        case Saml2SecurityAlgorithms.Sha256Digest:
                            padding = RSAEncryptionPadding.OaepSHA256;
                            break;
                        case Saml2SecurityAlgorithms.Sha384Digest:
                            padding = RSAEncryptionPadding.OaepSHA384;
                            break;
                        case Saml2SecurityAlgorithms.Sha512Digest:
                            padding = RSAEncryptionPadding.OaepSHA512;
                            break;
                    }
                }
                key = EncryptionPrivateKey.Decrypt(encryptedKey.CipherData.CipherValue, padding);
            }
            else
                key = DecryptKey(encryptedKey.CipherData.CipherValue, EncryptionPrivateKey, (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl));
            return key;
        }
    }
}
