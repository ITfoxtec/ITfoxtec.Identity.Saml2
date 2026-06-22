using ITfoxtec.Identity.Saml2.Cryptography;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Extension methods for Saml2X509Certificate.
    /// </summary>
    public static class X509Certificate2Extensions
    {
        /// <summary>
        /// Get the private RSA key from either Saml2X509Certificate or X509Certificate2.
        /// </summary>
        public static RSA GetSamlRSAPrivateKey(this X509Certificate2 certificate)
        {
            if(certificate is Saml2X509Certificate)
            {
                return (certificate as Saml2X509Certificate).GetRSAPrivateKey();
            }
            else
            {
                return certificate.GetRSAPrivateKey();
            }
        }

        public static AsymmetricAlgorithm GetSamlPrivateKey(this X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (Cryptography.SignatureAlgorithm.IsRsaAlgorithm(signatureAlgorithm))
            {
                return certificate.GetSamlRSAPrivateKey();
            }

#if NET && !NET70 && !NET60
            if (Cryptography.SignatureAlgorithm.IsEcdsaAlgorithm(signatureAlgorithm))
            {
                return certificate.GetECDsaPrivateKey();
            }
#endif

            Cryptography.SignatureAlgorithm.ValidateAlgorithm(signatureAlgorithm);
            throw new InvalidOperationException();
        }

        public static AsymmetricAlgorithm GetSamlPublicKey(this X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (Cryptography.SignatureAlgorithm.IsRsaAlgorithm(signatureAlgorithm))
            {
                return certificate.GetRSAPublicKey();
            }

#if NET && !NET70 && !NET60
            if (Cryptography.SignatureAlgorithm.IsEcdsaAlgorithm(signatureAlgorithm))
            {
                return certificate.GetECDsaPublicKey();
            }
#endif

            Cryptography.SignatureAlgorithm.ValidateAlgorithm(signatureAlgorithm);
            throw new InvalidOperationException();
        }

        /// <summary>
        /// Validates if the certificate is expired in relation to local time.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <returns>Return true if the certificate is valid / not expired.</returns>
        public static bool IsValidLocalTime(this X509Certificate2 certificate)
        {
            var nowLocal = DateTime.Now;
            if (certificate.NotBefore <= nowLocal && certificate.NotAfter >= nowLocal)
            {
                return true;
            }

            return false;
        }
    }
}
