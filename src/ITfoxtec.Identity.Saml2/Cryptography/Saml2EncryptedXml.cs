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

#if !NETFULL
        static Saml2EncryptedXml()
        {
            // Register AES-GCM wrapper on .NET Core targets where AES-GCM algorithm is available
            CryptoConfig.AddAlgorithm(typeof(AesGcmAlgorithm), AesGcmAlgorithm.AesGcm256Identifier);
            CryptoConfig.AddAlgorithm(typeof(AesGcmAlgorithm), AesGcmAlgorithm.AesGcm128Identifier);
        }
#endif

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

        public virtual XmlElement EncryptAassertion(XmlElement assertionElement, string encryptionMethod)
        {
            using (var encryptionAlgorithm = Aes.Create())
            {
                encryptionMethod = string.IsNullOrEmpty(encryptionMethod)
                    ? Saml2EncryptionAlgorithms.XmlEncAES256Url
                    : encryptionMethod;
                switch (encryptionMethod)
                {
                    case Saml2EncryptionAlgorithms.XmlEncAES128Url:
                    case Saml2EncryptionAlgorithms.XmlEncAES128KeyWrapUrl:
                        encryptionAlgorithm.KeySize = 128; break;
                    case Saml2EncryptionAlgorithms.XmlEncAES192Url:
                    case Saml2EncryptionAlgorithms.XmlEncAES192KeyWrapUrl:
                        encryptionAlgorithm.KeySize = 192; break;
                    case Saml2EncryptionAlgorithms.XmlEncSHA512Url:
                        encryptionAlgorithm.KeySize = 512; break;
                    default:
                        encryptionAlgorithm.KeySize = 256; break;
                }

                var encryptedData = new EncryptedData
                {
                    Type = XmlEncElementUrl,
                    EncryptionMethod = new EncryptionMethod(encryptionMethod),
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

        public override byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (encryptedData is null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

#if !NETFULL

            var aesGcmSymmetricAlgorithmUri = symmetricAlgorithmUri ?? encryptedData.EncryptionMethod?.KeyAlgorithm;
            if (aesGcmSymmetricAlgorithmUri == AesGcmAlgorithm.AesGcm128Identifier || aesGcmSymmetricAlgorithmUri == AesGcmAlgorithm.AesGcm256Identifier)
            {
                int initBytesSize = 12;
                byte[] iv = new byte[initBytesSize];
                Buffer.BlockCopy(encryptedData.CipherData.CipherValue, 0, iv, 0, iv.Length);
                return iv;
            }
#endif

            return base.GetDecryptionIV(encryptedData, symmetricAlgorithmUri);
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
