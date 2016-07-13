using System;
using System.IdentityModel.Tokens;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public static class SignatureAlgorithm
    {
        public static void ValidateAlgorithm(string signatureAlgorithm)
        {
            if (!SecurityAlgorithms.RsaSha1Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture) && !SecurityAlgorithms.RsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                throw new NotSupportedException($"Only SHA1 ({SecurityAlgorithms.RsaSha1Signature}) and SHA256 ({SecurityAlgorithms.RsaSha256Signature}) is supported.");
            }
        }

        public static string DigestMethod(string signatureAlgorithm)
        {
            if (SecurityAlgorithms.RsaSha1Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SecurityAlgorithms.Sha1Digest;
            }
            else if (SecurityAlgorithms.RsaSha256Signature.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SecurityAlgorithms.Sha256Digest;
            }
            else
            {
                ValidateAlgorithm(signatureAlgorithm);
                throw new InvalidOperationException();
            }
        }
    }
}
