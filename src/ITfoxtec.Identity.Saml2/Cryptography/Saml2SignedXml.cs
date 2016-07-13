using System;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2SignedXml : SignedXml
    {
        public XmlElement Element { get; protected set; }
        public Saml2Signer saml2Signer { get; protected set; }

        public Saml2SignedXml(XmlElement element, X509Certificate2 certificate, string signatureAlgorithm) : base(element)
        {
            if (element == null) throw new ArgumentNullException(nameof(element));
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            Element = element;
            saml2Signer = new Saml2Signer(certificate, signatureAlgorithm);
        }

        public void ComputeSignature(X509IncludeOption includeOption, string id)
        {
            SignedInfo.SignatureMethod = saml2Signer.SignatureAlgorithm;
            SignedInfo.CanonicalizationMethod = XmlDsigExcC14NTransformUrl;

            var reference = new Reference("#" + id);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = SignatureAlgorithm.DigestMethod(saml2Signer.SignatureAlgorithm);
            AddReference(reference);

            // SignedXml do not support SHA256 this is a hack to support both SHA1 and SHA256
            ComputeSignatureInternal();

            KeyInfo = new KeyInfo();
            KeyInfo.AddClause(new KeyInfoX509Data(saml2Signer.Certificate, includeOption));
        }

        public new bool CheckSignature()
        {
            ValidateSignature();

            var signatureAlgorithm = saml2Signer.SignatureAlgorithm;
            var actualAignatureAlgorithm = m_signature.SignedInfo.SignatureMethod;
            if (signatureAlgorithm == null)
            {
                signatureAlgorithm = actualAignatureAlgorithm;
                SignatureAlgorithm.ValidateAlgorithm(signatureAlgorithm);
            }
            else if (!signatureAlgorithm.Equals(actualAignatureAlgorithm, StringComparison.InvariantCulture))
            {
                throw new CryptographicException($"Signature Algorithm do not match. Expected algorithm {signatureAlgorithm} actual algorithm {actualAignatureAlgorithm}");
            }

            // SignedXml do not support SHA256 this is a hack to support both SHA1 and SHA256
            if (!CheckSignatureInternal(signatureAlgorithm))
            {
                return false;
            }

            return true;
        }

        private void ValidateSignature()
        {
            if (SignedInfo.References.Count != 1)
            {
                throw new CryptographicException("There is not exactly one Signature Reference.");
            }

            var reference = SignedInfo.References[0] as Reference;
            var referenceElement = GetIdElement(Element.OwnerDocument, reference.Uri.Substring(1));

            if (referenceElement != Element)
            {
                throw new CryptographicException("Signature Reference is Incorrect reference.");
            }
        }

        private void ComputeSignatureInternal()
        {
            BuildDigestedReferencesInvoker();

            var formatter = saml2Signer.CreateFormatter();
            byte[] hashvalue = GetC14NDigestInvoker(saml2Signer.HashAlgorithm);

            m_signature.SignatureValue = formatter.CreateSignature(hashvalue);
        }

        private bool CheckSignatureInternal(string signatureAlgorithm)
        {
            if (!CheckSignedInfoInternal(signatureAlgorithm))
            {
                return false;
            }

            if (!CheckDigestedReferencesInvoker())
            {
                return false;
            }

            return true;
        }

        private bool CheckSignedInfoInternal(string signatureAlgorithm)
        {
            var deformatter = saml2Signer.CreateDeformatter(signatureAlgorithm);
            byte[] hashvalue = GetC14NDigestInvoker(saml2Signer.HashAlgorithm);

            return deformatter.VerifySignature(hashvalue, m_signature.SignatureValue);
        }

        private void BuildDigestedReferencesInvoker()
        {
            typeof(SignedXml).InvokeMember("BuildDigestedReferences", BindingFlags.Instance | BindingFlags.InvokeMethod | BindingFlags.NonPublic, null, this, null);
        }

        private byte[] GetC14NDigestInvoker(HashAlgorithm hash)
        {
            return (byte[])typeof(SignedXml).InvokeMember("GetC14NDigest", BindingFlags.Instance | BindingFlags.InvokeMethod | BindingFlags.NonPublic, null, this, new object[] { hash });
        }

        private bool CheckDigestedReferencesInvoker()
        {
            return (bool)typeof(SignedXml).InvokeMember("CheckDigestedReferences", BindingFlags.Instance | BindingFlags.InvokeMethod | BindingFlags.NonPublic, null, this, null);
        }
    }
}
