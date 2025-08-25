using ITfoxtec.Identity.Saml2.Schemas;
using System;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public static class EncryptionAlgorithm
    {
        public static void ValidateAlgorithm(string encryptionAlgorithm)
        {
            // --- Symmetric Block Encryption ---
            if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES128Url, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES256Url, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES192Url, StringComparison.InvariantCulture))
            {
                throw new NotSupportedException("AES192 is rarely supported in SAML deployments. Use AES128 or AES256 instead.");
            }

            // --- Symmetric Key Wrap ---
            else if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES128KeyWrapUrl, StringComparison.InvariantCulture) ||
                     encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES256KeyWrapUrl, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncAES192KeyWrapUrl, StringComparison.InvariantCulture))
            {
                throw new NotSupportedException("AES192 Key Wrap is rarely supported. Use AES128 or AES256 Key Wrap instead.");
            }

            // --- Message Digest ---
            else if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncSHA256Url, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (encryptionAlgorithm.Equals(Saml2EncryptionAlgorithms.XmlEncSHA512Url, StringComparison.InvariantCulture))
            {
                return;
            }
            throw new NotSupportedException($"Unsupported encryption algorithm: {encryptionAlgorithm}");
        }
    }
}
