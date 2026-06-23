using System;
using System.Collections.Generic;
using System.Linq;
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
        public IEnumerable<string> SignatureValidationAlgorithms { get; protected set; }
        public IEnumerable<string> XmlCanonicalizationValidationMethods { get; protected set; }
        public string ActualSignatureMethod => SignedInfo?.SignatureMethod;

        public Saml2SignedXml(XmlElement element, X509Certificate2 certificate, string signatureAlgorithm, string canonicalizationMethod) : base(element)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureAlgorithm == null) throw new ArgumentNullException(nameof(signatureAlgorithm));
            if (canonicalizationMethod == null) throw new ArgumentNullException(nameof(canonicalizationMethod));

            Element = element;
            CanonicalizationMethod = canonicalizationMethod;
            SignatureValidationAlgorithms = new[] { signatureAlgorithm };
            XmlCanonicalizationValidationMethods = new[] { canonicalizationMethod };
            Saml2Signer = new Saml2Signer(certificate, signatureAlgorithm);
        }

        public Saml2SignedXml(XmlElement element, X509Certificate2 certificate, IEnumerable<string> signatureValidationAlgorithms, IEnumerable<string> xmlCanonicalizationValidationMethods) : base(element)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (signatureValidationAlgorithms == null) throw new ArgumentNullException(nameof(signatureValidationAlgorithms));
            if (xmlCanonicalizationValidationMethods == null) throw new ArgumentNullException(nameof(xmlCanonicalizationValidationMethods));

            Element = element;
            SignatureValidationAlgorithms = signatureValidationAlgorithms.ToList();
            XmlCanonicalizationValidationMethods = xmlCanonicalizationValidationMethods.ToList();
            if (!SignatureValidationAlgorithms.Any())
            {
                throw new ArgumentException("At least one signature validation algorithm is required.", nameof(signatureValidationAlgorithms));
            }
            if (!XmlCanonicalizationValidationMethods.Any())
            {
                throw new ArgumentException("At least one XML canonicalization validation method is required.", nameof(xmlCanonicalizationValidationMethods));
            }
            Saml2Signer = new Saml2Signer(certificate, SignatureValidationAlgorithms.First());
        }

        public void ComputeSignature(X509IncludeOption includeOption, string id, bool includeKeyInfoName)
        {
            var reference = new Reference("#" + id);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.DigestMethod = SignatureAlgorithm.DigestMethod(Saml2Signer.SignatureAlgorithm);
            reference.AddTransform(XmlCanonicalizationMethod.GetTransform(CanonicalizationMethod));
            SignedInfo.CanonicalizationMethod = CanonicalizationMethod;

            AddReference(reference);
            SignedInfo.SignatureMethod = Saml2Signer.SignatureAlgorithm;
            SigningKey = Saml2Signer.Certificate.GetSamlPrivateKey(Saml2Signer.SignatureAlgorithm);
            ComputeSignature();

            KeyInfo = new KeyInfo();
            if (includeKeyInfoName)
            {
                KeyInfo.AddClause(new KeyInfoName(Convert.ToBase64String(Saml2Signer.Certificate.GetCertHash())));
            }
            KeyInfo.AddClause(new KeyInfoX509Data(Saml2Signer.Certificate, includeOption));
        }

        public new bool CheckSignature()
        {
            var signatureMethod = SignedInfo.SignatureMethod;
            var canonicalizationMethod = SignedInfo.CanonicalizationMethod;

            if (SignedInfo.References.Count != 1)
            {
                throw new InvalidSignatureException("Invalid XML signature reference.");
            }

            ValidateSignatureMethod(signatureMethod);
            ValidateCanonicalizationMethod(canonicalizationMethod);

            var reference = SignedInfo.References[0] as Reference;
            AssertReferenceValid(reference);

            var publicKey = Saml2Signer.Certificate.GetSamlPublicKey(signatureMethod);
            if (publicKey == null)
            {
                throw new InvalidSignatureException($"No matching public key present in Signature Validation Certificate for signature method {signatureMethod}.");
            }

            return CheckSignature(publicKey);
        }

        private void ValidateSignatureMethod(string signatureMethod)
        {
            if (string.IsNullOrWhiteSpace(signatureMethod))
            {
                throw new InvalidSignatureException("Signature method is missing.");
            }

            try
            {
                SignatureAlgorithm.ValidateAlgorithm(signatureMethod);
            }
            catch (NotSupportedException ex)
            {
                throw new InvalidSignatureException($"Illegal signature method {signatureMethod} used in signature.", ex);
            }

            if (!SignatureValidationAlgorithms.Contains(signatureMethod, StringComparer.InvariantCulture))
            {
                throw new InvalidSignatureException($"Illegal signature method {signatureMethod} used in signature.");
            }
        }

        private void ValidateCanonicalizationMethod(string canonicalizationMethod)
        {
            if (string.IsNullOrWhiteSpace(canonicalizationMethod))
            {
                throw new InvalidSignatureException("Canonicalization method is missing.");
            }

            try
            {
                XmlCanonicalizationMethod.ValidateCanonicalizationMethod(canonicalizationMethod);
            }
            catch (NotSupportedException ex)
            {
                throw new InvalidSignatureException($"Illegal canonicalization method {canonicalizationMethod} used in signature.", ex);
            }

            if (!XmlCanonicalizationValidationMethods.Contains(canonicalizationMethod, StringComparer.InvariantCulture))
            {
                throw new InvalidSignatureException($"Illegal canonicalization method {canonicalizationMethod} used in signature.");
            }
        }

        private void AssertReferenceValid(Reference reference)
        {
            var referenceId = reference.Uri.Substring(1);
            if (Element != GetIdElement(Element.OwnerDocument, referenceId))
            {
                throw new InvalidSignatureException("XML signature reference do not refer to the root element.");
            }

            AssertTransformChainValid(reference.TransformChain);
        }

        private void AssertTransformChainValid(TransformChain transformChain)
        {
            foreach (Transform transform in transformChain)
            {
                var algorithm = transform.Algorithm;
                if (algorithm == XmlDsigEnvelopedSignatureTransformUrl)
                {
                    continue;
                }

                try
                {
                    XmlCanonicalizationMethod.ValidateCanonicalizationMethod(algorithm);
                }
                catch (NotSupportedException ex)
                {
                    throw new InvalidSignatureException($"Illegal transform method {algorithm} used in signature.", ex);
                }

                if (!XmlCanonicalizationValidationMethods.Contains(algorithm, StringComparer.InvariantCulture))
                {
                    throw new InvalidSignatureException($"Illegal transform method {algorithm} used in signature.");
                }
            }
        }
    }
}
