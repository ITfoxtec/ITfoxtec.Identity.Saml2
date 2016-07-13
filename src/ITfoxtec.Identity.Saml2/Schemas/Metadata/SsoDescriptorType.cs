using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The SSODescriptorType abstract type is a common base type for the concrete types
    /// SPSSODescriptorType and IDPSSODescriptorType, described in subsequent sections. It extends
    /// RoleDescriptorType with elements reflecting profiles common to both identity providers and service
    /// providers that support SSO.
    /// </summary>
    public abstract class SsoDescriptorType
    {
        /// <summary>
        /// A whitespace-delimited set of URIs that identify the set of protocol specifications supported by the
        /// role element. For SAML V2.0 entities, this set MUST include the SAML protocol namespace URI,
        /// urn:oasis:names:tc:SAML:2.0:protocol. 
        /// </summary>
        protected internal string protocolSupportEnumeration = Saml2Constants.ProtocolNamespace.OriginalString;

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; } = X509IncludeOption.EndCertOnly;

        /// <summary>
        /// [Optional]
        /// Signing Certificate for Key Descriptor
        /// </summary>
        public IEnumerable<X509Certificate2> SigningCertificates { get; set; }

        /// <summary>
        /// [Optional]
        /// Encryption Certificate for Key Descriptor
        /// </summary>
        public IEnumerable<X509Certificate2> EncryptionCertificates { get; set; }

        /// <summary>
        /// [Optional]
        /// Zero or one element of type EndpointType that describe endpoints that support the Single
        /// Logout profiles defined in [SAMLProf].
        /// </summary>
        public IEnumerable<SingleLogoutService> SingleLogoutServices { get; set; }

        /// <summary>
        /// [Optional]
        /// Zero or one element of type anyURI that enumerate the name identifier formats supported by
        /// this system entity acting in this role. See Section 8.3 of [SAMLCore] for some possible values for
        /// this element.
        /// </summary>
        public IEnumerable<Uri> NameIDFormats { get; set; }

        protected XObject KeyDescriptor(X509Certificate2 certificate, string keyType)
        {
            var keyinfo = new KeyInfo();
            keyinfo.AddClause(new KeyInfoX509Data(certificate, CertificateIncludeOption));

            return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.KeyDescriptor,
                new XAttribute(Saml2MetadataConstants.Message.Use, keyType),
                XElement.Parse(keyinfo.GetXml().OuterXml));
        }
    }
}
