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

        public override byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (symmetricAlgorithmUri == null)
                symmetricAlgorithmUri = encryptedData?.EncryptionMethod?.KeyAlgorithm;
            if (symmetricAlgorithmUri==AesGcmAlgorithm.AesGcm128Identifier || symmetricAlgorithmUri == AesGcmAlgorithm.AesGcm256Identifier)
            {
                if (encryptedData == null)
                    throw new ArgumentNullException(nameof(encryptedData));

                int initBytesSize = 12;
                byte[] iv = new byte[initBytesSize];
                Buffer.BlockCopy(encryptedData.CipherData.CipherValue, 0, iv, 0, iv.Length);
                return iv;
            } else
                return base.GetDecryptionIV(encryptedData, symmetricAlgorithmUri);
        }

        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            return DecryptKey(encryptedKey.CipherData.CipherValue, EncryptionPrivateKey, (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl));
        }
    }
}
