using ITfoxtec.Identity.Saml2.Schemas;
using System;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public static class EncryptionAlgorithm
    {
        public static void ValidateAlgorithm(string encryptionAlgorithm)
        {
            ValidateDataEncryptionAlgorithm(encryptionAlgorithm);
        }

        public static void ValidateDataEncryptionAlgorithm(string encryptionAlgorithm)
        {
            if (string.IsNullOrWhiteSpace(encryptionAlgorithm)) throw new ArgumentNullException(nameof(encryptionAlgorithm));

            // --- Symmetric Block Encryption ---
            if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES128Url, StringComparison.InvariantCulture) || 
                encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES192Url, StringComparison.InvariantCulture) ||
                encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES256Url, StringComparison.InvariantCulture) ||
                encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl, StringComparison.InvariantCulture) ||
                encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl, StringComparison.InvariantCulture) ||
                encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl, StringComparison.InvariantCulture))
            {
                return;
            }

            throw new NotSupportedException($"Unsupported data encryption algorithm: {encryptionAlgorithm}");
        }

        public static void ValidateKeyEncryptionAlgorithm(string keyEncryptionAlgorithm)
        {
            if (string.IsNullOrWhiteSpace(keyEncryptionAlgorithm)) throw new ArgumentNullException(nameof(keyEncryptionAlgorithm));

            // --- Key Transport ---
            if (keyEncryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncRSA15Url, StringComparison.InvariantCulture) ||
                keyEncryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl, StringComparison.InvariantCulture) ||
                keyEncryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url, StringComparison.InvariantCulture))
            {
                return;
            }

            throw new NotSupportedException($"Unsupported key encryption algorithm: {keyEncryptionAlgorithm}");
        }
    }
}
