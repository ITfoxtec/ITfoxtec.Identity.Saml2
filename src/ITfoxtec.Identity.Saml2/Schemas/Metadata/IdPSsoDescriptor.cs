using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The IDPSSODescriptor element extends SSODescriptorType with content reflecting profiles specific 
    /// to identity providers supporting SSO.
    /// </summary>
    public class IdPSsoDescriptor : SsoDescriptorType
    {
        const string elementName = Saml2MetadataConstants.Message.IdPSsoDescriptor;

        /// <summary>
        /// [Optional]
        /// Optional attribute that indicates to service providers whether or not they can expect an 
        /// unsigned &lt;AuthnRequest&gt; message to be accepted by the identity provider. 
        /// If omitted, the value is assumed to be false.
        /// </summary>
        public bool? WantAuthnRequestsSigned { get; set; }

        /// <summary>
        /// One or more elements of type EndpointType that describe endpoints that support the profiles of the 
        /// Authentication Request protocol defined in [SAMLProf]. All identity providers support at least one 
        /// such endpoint, by definition. The ResponseLocation attribute MUST be omitted. 
        /// </summary>
        public IEnumerable<SingleSignOnService> SingleSignOnServices { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.ProtocolSupportEnumeration, protocolSupportEnumeration);

            if (WantAuthnRequestsSigned.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.WantAuthnRequestsSigned, WantAuthnRequestsSigned.Value);
            }

            if (EncryptionCertificates != null)
            {
                foreach (var encryptionCertificate in EncryptionCertificates)
                {
                    yield return KeyDescriptor(encryptionCertificate, Saml2MetadataConstants.KeyTypes.Encryption, EncryptionMethods);
                }
            }

            if (SigningCertificates != null)
            {
                foreach (var signingCertificate in SigningCertificates)
                {
                    yield return KeyDescriptor(signingCertificate, Saml2MetadataConstants.KeyTypes.Signing);
                }
            }

            if (SingleLogoutServices != null)
            {
                foreach (var singleLogoutService in SingleLogoutServices)
                {
                    yield return singleLogoutService.ToXElement();
                }
            }

            if (NameIDFormats != null)
            {
                foreach (var nameIDFormat in NameIDFormats)
                {
                    yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.NameIDFormat, nameIDFormat.OriginalString);
                }
            }

            if (SingleSignOnServices != null)
            {
                foreach (var singleSignOnService in SingleSignOnServices)
                {
                    yield return singleSignOnService.ToXElement();
                }
            }
        }

        protected internal IdPSsoDescriptor Read(XmlElement xmlElement)
        {
            WantAuthnRequestsSigned = xmlElement.Attributes[Saml2MetadataConstants.Message.WantAuthnRequestsSigned]?.Value.Equals(true.ToString(), StringComparison.InvariantCultureIgnoreCase);

            ReadKeyDescriptors(xmlElement);

            var singleSignOnServiceElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.SingleSignOnService}']");
            if (singleSignOnServiceElements != null)
            {
                SingleSignOnServices = ReadServices<SingleSignOnService>(singleSignOnServiceElements);
            }

            ReadSingleLogoutService(xmlElement);

            ReadNameIDFormat(xmlElement);

            return this;
        }      
    }
}
