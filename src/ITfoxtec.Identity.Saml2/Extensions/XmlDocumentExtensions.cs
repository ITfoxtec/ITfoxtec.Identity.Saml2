using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
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
            xmlDocument.DocumentElement.InsertAfter(xmlDocument.ImportNode(signedXml.GetXml(), true), issuer);
            return xmlDocument;
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