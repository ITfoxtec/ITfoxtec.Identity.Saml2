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

            throw new NotSupportedException($"Only SHA1 ({Saml2SecurityAlgorithms.RsaSha1Signature}), SHA256 ({Saml2SecurityAlgorithms.RsaSha256Signature}), SHA384 ({Saml2SecurityAlgorithms.RsaSha384Signature}) and SHA512 ({Saml2SecurityAlgorithms.RsaSha512Signature}) is supported.");
        }

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
            else
            {
                ValidateAlgorithm(signatureAlgorithm);
                throw new InvalidOperationException();
            }
        }
    }
}
