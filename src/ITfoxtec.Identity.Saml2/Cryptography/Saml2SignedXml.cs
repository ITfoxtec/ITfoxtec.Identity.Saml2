using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2SignedXml : SignedXml
    {
        public Saml2Signer Saml2Signer { get; protected set; }

        public Saml2SignedXml(XmlElement element, X509Certificate2 certificate, string signatureAlgorithm) : base(element)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureAlgorithm == null) throw new ArgumentNullException(nameof(signatureAlgorithm));

            Saml2Signer = new Saml2Signer(certificate, signatureAlgorithm);
        }

        public void ComputeSignature(X509IncludeOption includeOption, string id)
        {
            var reference = new Reference("#" + id);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = SignatureAlgorithm.DigestMethod(Saml2Signer.SignatureAlgorithm);
            AddReference(reference);

            SignedInfo.CanonicalizationMethod = XmlDsigExcC14NTransformUrl;
            SignedInfo.SignatureMethod = Saml2Signer.SignatureAlgorithm;
            SigningKey = Saml2Signer.Certificate.GetRSAPrivateKey();
            ComputeSignature();

            KeyInfo = new KeyInfo();
            KeyInfo.AddClause(new KeyInfoX509Data(Saml2Signer.Certificate, includeOption));
        }

        public new bool CheckSignature()
        {
            var canonicalizationMethodValid = SignedInfo.CanonicalizationMethod == XmlDsigExcC14NTransformUrl;
            var signatureMethodValid = SignedInfo.SignatureMethod == Saml2Signer.SignatureAlgorithm;
            if (!(canonicalizationMethodValid && signatureMethodValid))
            {
                return false;
            }
            else
            {
                return CheckSignature(Saml2Signer.Certificate, true);
            }
        }
    }
}
