using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#if !NETFULL
using ITfoxtec.Identity.Saml2.Schemas;
#endif

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2Signer
    {
        public X509Certificate2 Certificate { get; protected set; }

        public string SignatureAlgorithm { get; set; }

#if !NETFULL
        static Saml2Signer()
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), Saml2SecurityAlgorithms.RsaSha256Signature);
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA384SignatureDescription), Saml2SecurityAlgorithms.RsaSha384Signature);
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA512SignatureDescription), Saml2SecurityAlgorithms.RsaSha512Signature);
        }
#endif

        public Saml2Signer(X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureAlgorithm == null) throw new ArgumentNullException(nameof(signatureAlgorithm));

            Certificate = certificate;
            SignatureAlgorithm = signatureAlgorithm;
        }

        public (AsymmetricSignatureFormatter, HashAlgorithm) CreateFormatter()
        {
            (var signatureDescription, var hashAlgorithm) = GetSignatureDescription();
            var formatter = signatureDescription.CreateFormatter(Certificate.GetSamlRSAPrivateKey());
            return (formatter, hashAlgorithm);
        }

        public (AsymmetricSignatureDeformatter, HashAlgorithm) CreateDeformatter()
        {
            (var signatureDescription, var hashAlgorithm) = GetSignatureDescription();
            var deformatter = signatureDescription.CreateDeformatter(Certificate.GetRSAPublicKey());
            return (deformatter, hashAlgorithm);
        }

        private (SignatureDescription, HashAlgorithm) GetSignatureDescription()
        {
            var signatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(SignatureAlgorithm);
            var hashAlgorithm = signatureDescription.CreateDigest();
            return (signatureDescription, hashAlgorithm);
        }
    }
}
