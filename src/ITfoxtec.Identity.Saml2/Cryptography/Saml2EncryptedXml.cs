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

#if !NETFULL
        static Saml2EncryptedXml()
        {
            // Register AES-GCM wrapper on .NET Core targets where AES-GCM algorithm is available
            CryptoConfig.AddAlgorithm(typeof(AesGcmAlgorithm), AesGcmAlgorithm.AesGcm256Identifier);
            CryptoConfig.AddAlgorithm(typeof(AesGcmAlgorithm), AesGcmAlgorithm.AesGcm192Identifier);
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

        public virtual XmlElement EncryptAassertion(XmlElement assertionElement, string encryptionMethod = Saml2EncryptionAlgorithms.XmlEncAES256Url, string keyEncryptionMethod = Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl)
        {
            EncryptionAlgorithm.ValidateDataEncryptionAlgorithm(encryptionMethod);
            EncryptionAlgorithm.ValidateKeyEncryptionAlgorithm(keyEncryptionMethod);

            using (var encryptionAlgorithm = CreateEncryptionAlgorithm(encryptionMethod))
            {
                var encryptedData = new EncryptedData
                {
                    Type = XmlEncElementUrl,
                    EncryptionMethod = new EncryptionMethod(encryptionMethod),
                    KeyInfo = new KeyInfo()
                };
                encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(new EncryptedKey
                {
                    EncryptionMethod = new EncryptionMethod(keyEncryptionMethod),
                    CipherData = new CipherData(EncryptKey(encryptionAlgorithm.Key, EncryptionPublicKey, keyEncryptionMethod))
                }));

                var encryptedXml = new EncryptedXml();
                encryptedData.CipherData.CipherValue = encryptedXml.EncryptData(assertionElement, encryptionAlgorithm, false);

                var encryptedDataXml = encryptedData.GetXml();
                AddKeyEncryptionMethodChildren(encryptedDataXml, keyEncryptionMethod);
                return encryptedDataXml;
            }
        }

        private static SymmetricAlgorithm CreateEncryptionAlgorithm(string encryptionMethod)
        {
#if !NETFULL
            if (IsAesGcmAlgorithm(encryptionMethod))
            {
                var aesGcmAlgorithm = new AesGcmAlgorithm
                {
                    KeySize = GetAesKeySize(encryptionMethod)
                };
                aesGcmAlgorithm.GenerateKey();
                aesGcmAlgorithm.GenerateIV();
                return aesGcmAlgorithm;
            }
#else
            if (IsAesGcmAlgorithm(encryptionMethod))
            {
                throw new NotSupportedException($"Unsupported encryption algorithm on .NET Framework: {encryptionMethod}");
            }
#endif

            var encryptionAlgorithm = Aes.Create();
            encryptionAlgorithm.KeySize = GetAesKeySize(encryptionMethod);
            return encryptionAlgorithm;
        }

        private static int GetAesKeySize(string encryptionMethod)
        {
            switch (encryptionMethod)
            {
                case Saml2EncryptionAlgorithms.XmlEncAES128Url:
                case Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl:
                    return 128;
                case Saml2EncryptionAlgorithms.XmlEncAES192Url:
                case Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl:
                    return 192;
                case Saml2EncryptionAlgorithms.XmlEncAES256Url:
                case Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl:
                    return 256;
                default:
                    throw new NotSupportedException($"Unsupported encryption algorithm: {encryptionMethod}");
            }
        }

        private static byte[] EncryptKey(byte[] keyData, RSA rsa, string keyEncryptionMethod)
        {
            switch (keyEncryptionMethod)
            {
                case Saml2EncryptionAlgorithms.XmlEncRSA15Url:
                    return EncryptKey(keyData, rsa, false);
                case Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl:
                    return EncryptKey(keyData, rsa, true);
                case Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url:
                    return rsa.Encrypt(keyData, RSAEncryptionPadding.OaepSHA256);
                default:
                    throw new NotSupportedException($"Unsupported key encryption algorithm: {keyEncryptionMethod}");
            }
        }

        private static void AddKeyEncryptionMethodChildren(XmlElement encryptedDataXml, string keyEncryptionMethod)
        {
            if (keyEncryptionMethod != Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url)
            {
                return;
            }

            var nsm = new XmlNamespaceManager(encryptedDataXml.OwnerDocument.NameTable);
            nsm.AddNamespace("enc", XmlEncNamespaceUrl);
            var keyEncryptionMethodElement = encryptedDataXml.SelectSingleNode("descendant::enc:EncryptedKey/enc:EncryptionMethod", nsm) as XmlElement;
            if (keyEncryptionMethodElement == null)
            {
                return;
            }

            var digestMethodElement = encryptedDataXml.OwnerDocument.CreateElement("ds", "DigestMethod", SignedXml.XmlDsigNamespaceUrl);
            digestMethodElement.SetAttribute("Algorithm", Saml2SecurityAlgorithms.Sha256Digest);
            keyEncryptionMethodElement.AppendChild(digestMethodElement);

            var mgfElement = encryptedDataXml.OwnerDocument.CreateElement("xenc11", "MGF", "http://www.w3.org/2009/xmlenc11#");
            mgfElement.SetAttribute("Algorithm", Saml2EncryptionAlgorithms.XmlEncMGF1SHA256Url);
            keyEncryptionMethodElement.AppendChild(mgfElement);
        }

        private static bool IsAesGcmAlgorithm(string encryptionMethod)
        {
            return encryptionMethod == Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl ||
                   encryptionMethod == Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl ||
                   encryptionMethod == Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl;
        }

        public override byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (encryptedData is null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

#if !NETFULL

            var aesGcmSymmetricAlgorithmUri = symmetricAlgorithmUri ?? encryptedData.EncryptionMethod?.KeyAlgorithm;
            if (aesGcmSymmetricAlgorithmUri == Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl ||
                aesGcmSymmetricAlgorithmUri == Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl ||
                aesGcmSymmetricAlgorithmUri == Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl)
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
            if (encryptedKey.EncryptionMethod.KeyAlgorithm == Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url)
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
