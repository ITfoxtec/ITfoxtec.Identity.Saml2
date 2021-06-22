using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2SignedXml : SignedXml
    {
        public XmlElement Element { get; protected set; }
        public Saml2Signer Saml2Signer { get; protected set; }
        public string CanonicalizationMethod { get; protected set; }

        public Saml2SignedXml(XmlElement element, X509Certificate2 certificate, string signatureAlgorithm, string canonicalizationMethod) : base(element)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureAlgorithm == null) throw new ArgumentNullException(nameof(signatureAlgorithm));
            if (canonicalizationMethod == null) throw new ArgumentNullException(nameof(canonicalizationMethod));

            Element = element;
            CanonicalizationMethod = canonicalizationMethod;
            Saml2Signer = new Saml2Signer(certificate, signatureAlgorithm);
        }

        public void ComputeSignature(X509IncludeOption includeOption, string id)
        {
            var reference = new Reference("#" + id);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.DigestMethod = SignatureAlgorithm.DigestMethod(Saml2Signer.SignatureAlgorithm);
            reference.AddTransform(XmlCanonicalizationMethod.GetTransform(CanonicalizationMethod));
            SignedInfo.CanonicalizationMethod = CanonicalizationMethod;

            AddReference(reference);
            SignedInfo.SignatureMethod = Saml2Signer.SignatureAlgorithm;
            SigningKey = Saml2Signer.Certificate.GetSamlRSAPrivateKey();
            ComputeSignature();

            KeyInfo = new KeyInfo();
            KeyInfo.AddClause(new KeyInfoX509Data(Saml2Signer.Certificate, includeOption));
        }

        public new bool CheckSignature()
        {
            if (SignedInfo.References.Count != 1)
            {
                throw new InvalidSignatureException("Invalid XML signature reference.");
            }

            var referenceId = (SignedInfo.References[0] as Reference).Uri.Substring(1);
            if (Element != GetIdElement(Element.OwnerDocument, referenceId))
            {
                throw new InvalidSignatureException("XML signature reference do not refer to the root element.");
            }

            var canonicalizationMethodValid = SignedInfo.CanonicalizationMethod == CanonicalizationMethod;
            var signatureMethodValid = SignedInfo.SignatureMethod == Saml2Signer.SignatureAlgorithm;
            if (!(canonicalizationMethodValid && signatureMethodValid))
            {
                return false;
            }
            else
            {                        
                return CheckSignature(Saml2Signer.Certificate.GetRSAPublicKey());
            }
        }
    }
}