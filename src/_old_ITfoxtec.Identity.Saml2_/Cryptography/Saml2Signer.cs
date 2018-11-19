using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2Signer
    {
        private SignatureDescription SignatureDescription { get; set; }

        public X509Certificate2 Certificate { get; protected set; }

        public string SignatureAlgorithm { get; set; }

        public HashAlgorithm HashAlgorithm { get; internal set; }


        public Saml2Signer(X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureAlgorithm == null) throw new ArgumentNullException(nameof(SignatureAlgorithm));

            Certificate = certificate;
            SignatureAlgorithm = signatureAlgorithm;
            SignatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(SignatureAlgorithm);
            HashAlgorithm = SignatureDescription.CreateDigest();
        }

        public AsymmetricSignatureFormatter CreateFormatter()
        {
            return SignatureDescription.CreateFormatter(Certificate.GetRSAPrivateKey());
        }

        public AsymmetricSignatureDeformatter CreateDeformatter()
        {
            return SignatureDescription.CreateDeformatter(Certificate.GetRSAPublicKey());
        }
    }
}
