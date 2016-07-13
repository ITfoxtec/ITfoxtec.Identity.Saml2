using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2Signer
    {
        public X509Certificate2 Certificate { get; protected set; }

        public X509AsymmetricSecurityKey Key { get; protected set; }

        public string SignatureAlgorithm { get; set; }

        public HashAlgorithm HashAlgorithm { get; internal set; }

        public AsymmetricSignatureFormatter Formatter { get; internal set; }

        public AsymmetricSignatureDeformatter Deformatter { get; internal set; }

        public Saml2Signer(X509Certificate2 certificate, string signatureAlgorithm = null)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            Certificate = certificate;
            Key = new X509AsymmetricSecurityKey(certificate);
            SignatureAlgorithm = signatureAlgorithm;
        }

        public AsymmetricSignatureFormatter CreateFormatter(string signatureAlgorithm = null)
        {
            UpdateSignatureAlgorithm(signatureAlgorithm);

            Formatter = Key.GetSignatureFormatter(SignatureAlgorithm);
            CreateHashAlgorithm();
            Formatter.SetHashAlgorithm(HashAlgorithm.GetType().ToString());
            return Formatter;
        }

        public AsymmetricSignatureDeformatter CreateDeformatter(string signatureAlgorithm = null)
        {
            UpdateSignatureAlgorithm(signatureAlgorithm);

            Deformatter = Key.GetSignatureDeformatter(SignatureAlgorithm);
            CreateHashAlgorithm();
            Deformatter.SetHashAlgorithm(HashAlgorithm.GetType().ToString());
            return Deformatter;
        }

        private void CreateHashAlgorithm()
        {
            HashAlgorithm = Key.GetHashAlgorithmForSignature(SignatureAlgorithm);
        }

        private void UpdateSignatureAlgorithm(string signatureAlgorithm)
        {
            if (signatureAlgorithm != null)
            {
                SignatureAlgorithm = signatureAlgorithm;
            }
            if (SignatureAlgorithm == null) throw new ArgumentNullException(nameof(SignatureAlgorithm));
        }
    }
}
