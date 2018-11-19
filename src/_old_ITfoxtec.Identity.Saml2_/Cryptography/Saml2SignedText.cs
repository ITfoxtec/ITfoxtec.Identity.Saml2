using System;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2SignedText
    {
        public Saml2Signer Saml2Signer { get; protected set; }

        public Saml2SignedText(X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            Saml2Signer = new Saml2Signer(certificate, signatureAlgorithm);
        }

        public byte[] SignData(byte[] input)
        {
            var formatter = Saml2Signer.CreateFormatter();
            return formatter.CreateSignature(Saml2Signer.HashAlgorithm.ComputeHash(input));
        }

        internal bool CheckSignature(byte[] input, byte[] signature)
        {
            var deformatter = Saml2Signer.CreateDeformatter();
            return deformatter.VerifySignature(Saml2Signer.HashAlgorithm.ComputeHash(input), signature);
        }
    }
}
