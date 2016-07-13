using System;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2SignedText
    {
        public Saml2Signer saml2Signer { get; protected set; }

        public Saml2SignedText(X509Certificate2 certificate, string signatureAlgorithm)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            saml2Signer = new Saml2Signer(certificate, signatureAlgorithm);
        }

        public byte[] SignData(byte[] input)
        {
            return saml2Signer.CreateFormatter().CreateSignature(saml2Signer.HashAlgorithm.ComputeHash(input));
        }

        internal bool CheckSignature(byte[] input, byte[] signature)
        {
            return saml2Signer.CreateDeformatter().VerifySignature(saml2Signer.HashAlgorithm.ComputeHash(input), signature);
        }
    }
}
