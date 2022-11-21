using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Extension methods for XmlDocument
    /// </summary>
    internal static class XmlDocumentExtensions
    {
        /// <summary>
        /// Signs an XmlDocument with an xml signature using the signing certificate given as argument to the method.
        /// </summary>
        /// <param name="certificate">The certificate used to sign the document</param>
        /// <param name="signatureAlgorithm">The Signature Algorithm used to sign the document</param>
        /// <param name="xmlCanonicalizationMethod">The Signature XML canonicalization method used to sign the document</param>
        /// <param name="includeOption">Certificate include option</param>
        /// <param name="id">The is of the topmost element in the xmldocument</param>
        internal static XmlDocument SignDocument(this XmlDocument xmlDocument, X509Certificate2 certificate, string signatureAlgorithm, string xmlCanonicalizationMethod, X509IncludeOption includeOption, string id)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var signedXml = new Saml2SignedXml(xmlDocument.DocumentElement, certificate, signatureAlgorithm, xmlCanonicalizationMethod);
            signedXml.ComputeSignature(includeOption, id);

            var issuer = xmlDocument.DocumentElement[Saml2Constants.Message.Issuer, Saml2Constants.AssertionNamespace.OriginalString];
            
            // workaround for adding ds: for signature

            // get signature xml and add "ds:" prefix
            var signature = signedXml.GetXml();
            SetPrefix("ds", signature);
            // Load modified signature back
            signedXml.LoadXml(signature);
            // this is workaround for overcoming a bug in the library
            signedXml.SignedInfo.References.Clear();
            // Recompute the signature
            signedXml.ComputeSignature();
            string recomputedSignature = Convert.ToBase64String(signedXml.SignatureValue);
            // Replace value of the signature with recomputed one
            ReplaceSignature(signature, recomputedSignature);

            xmlDocument.DocumentElement.InsertAfter(xmlDocument.ImportNode(signature, true), issuer);
            return xmlDocument;
        }

        private static void SetPrefix(string prefix, XmlNode node)
        {
            node.Prefix = prefix;
            foreach (XmlNode n in node.ChildNodes) {
                SetPrefix(prefix, n);
            }
        }

        private static void ReplaceSignature(XmlElement signature, string newValue)
        {
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (signature.OwnerDocument == null) throw new ArgumentException("No owner document", nameof(signature));

            XmlNamespaceManager nsm = new XmlNamespaceManager(signature.OwnerDocument.NameTable);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            XmlNode signatureValue = signature.SelectSingleNode("ds:SignatureValue", nsm);
            if (signatureValue == null)
                throw new Exception("Signature does not contain 'ds:SignatureValue'");

            signatureValue.InnerXml = newValue;
        }

        /// <summary>
        /// Signs an Xml assertion with an xml signature using the signing certificate given as argument to the method.
        /// </summary>
        /// <param name="certificate">The certificate used to sign the assertion</param>
        /// <param name="signatureAlgorithm">The Signature Algorithm used to sign the assertion</param>
        /// <param name="xmlCanonicalizationMethod">The Signature XML canonicalization method used to sign the assertion</param>
        /// <param name="includeOption">Certificate include option</param>
        internal static void SignAssertion(this XmlDocument xmlDocument, XmlElement xmlAssertionElement, X509Certificate2 certificate, string signatureAlgorithm, string xmlCanonicalizationMethod, X509IncludeOption includeOption)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var id = xmlAssertionElement.GetAttribute(Saml2Constants.Message.Id);

            var signedXml = new Saml2SignedXml(xmlAssertionElement, certificate, signatureAlgorithm, xmlCanonicalizationMethod);
            signedXml.ComputeSignature(includeOption, id);

            var issuer = xmlAssertionElement[Saml2Constants.Message.Issuer, Saml2Constants.AssertionNamespace.OriginalString];
            xmlAssertionElement.InsertAfter(xmlDocument.ImportNode(signedXml.GetXml(), true), issuer);
        }

        /// <summary>
        /// Converts an XmlDocument to an XDocument.
        /// </summary>
        internal static XDocument ToXDocument(this XmlDocument xmlDocument)
        {
            using (var reader = xmlDocument.CreateNavigator().ReadSubtree())
            {
                return XDocument.Load(reader);
            }
        }

        /// <summary>
        /// Converts an XmlDocument to an XElement.
        /// </summary>
        internal static XElement ToXElement(this XmlDocument xmlDocument)
        {
            using (var reader = xmlDocument.CreateNavigator().ReadSubtree())
            {
                return XElement.Load(reader);
            }
        }
    }
}