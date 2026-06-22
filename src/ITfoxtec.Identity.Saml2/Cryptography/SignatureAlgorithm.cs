using ITfoxtec.Identity.Saml2.Schemas;
using System;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public static class SignatureAlgorithm
    {
        public static void ValidateAlgorithm(string signatureAlgorithm)
        {            
            if (Saml2SecurityAlgorithms.RsaSha1Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (Saml2SecurityAlgorithms.RsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (Saml2SecurityAlgorithms.RsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (Saml2SecurityAlgorithms.RsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (Saml2SecurityAlgorithms.RsaPssSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
#if NET && !NET70 && !NET60
            else if (Saml2SecurityAlgorithms.EcdsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (Saml2SecurityAlgorithms.EcdsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (Saml2SecurityAlgorithms.EcdsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
#endif
#if NET && !NET70 && !NET60
            throw new NotSupportedException($"Only SHA1 ({Saml2SecurityAlgorithms.RsaSha1Signature}), SHA256 ({Saml2SecurityAlgorithms.RsaSha256Signature}), SHA384 ({Saml2SecurityAlgorithms.RsaSha384Signature}), SHA512 ({Saml2SecurityAlgorithms.RsaSha512Signature}), SHA256 RSA MGF1 ({Saml2SecurityAlgorithms.RsaPssSha256Signature}), ECDSA SHA256 ({Saml2SecurityAlgorithms.EcdsaSha256Signature}), ECDSA SHA384 ({Saml2SecurityAlgorithms.EcdsaSha384Signature}) and ECDSA SHA512 ({Saml2SecurityAlgorithms.EcdsaSha512Signature}) is supported.");
#else
            throw new NotSupportedException($"Only SHA1 ({Saml2SecurityAlgorithms.RsaSha1Signature}), SHA256 ({Saml2SecurityAlgorithms.RsaSha256Signature}), SHA384 ({Saml2SecurityAlgorithms.RsaSha384Signature}), SHA512 ({Saml2SecurityAlgorithms.RsaSha512Signature}) and SHA256 RSA MGF1 ({Saml2SecurityAlgorithms.RsaPssSha256Signature}) is supported.");
#endif

        }

        internal static bool IsRsaAlgorithm(string signatureAlgorithm)
        {
            if (Saml2SecurityAlgorithms.RsaSha1Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            else if (Saml2SecurityAlgorithms.RsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            else if (Saml2SecurityAlgorithms.RsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            else if (Saml2SecurityAlgorithms.RsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            else if (Saml2SecurityAlgorithms.RsaPssSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            return false;
        }

#if NET && !NET70 && !NET60
        internal static bool IsEcdsaAlgorithm(string signatureAlgorithm)
        {
            if (Saml2SecurityAlgorithms.EcdsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            else if (Saml2SecurityAlgorithms.EcdsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            else if (Saml2SecurityAlgorithms.EcdsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return true;
            }
            return false;
        }
#endif

        public static string DigestMethod(string signatureAlgorithm)
        {
            if (Saml2SecurityAlgorithms.RsaSha1Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha1Digest;
            }
            else if (Saml2SecurityAlgorithms.RsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha256Digest;
            }
            else if (Saml2SecurityAlgorithms.RsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha384Digest;
            }
            else if (Saml2SecurityAlgorithms.RsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha512Digest;
            }
            else if (Saml2SecurityAlgorithms.RsaPssSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha256Digest;
            }
#if NET && !NET70 && !NET60
            else if (Saml2SecurityAlgorithms.EcdsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha256Digest;
            }
            else if (Saml2SecurityAlgorithms.EcdsaSha384Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha384Digest;
            }
            else if (Saml2SecurityAlgorithms.EcdsaSha512Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return Saml2SecurityAlgorithms.Sha512Digest;
            }
#endif
            else
            {
                ValidateAlgorithm(signatureAlgorithm);
                throw new InvalidOperationException();
            }            
        }
    }
}
