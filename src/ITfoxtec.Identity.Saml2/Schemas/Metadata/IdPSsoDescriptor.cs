using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
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

            if (EncryptionCertificates != null)
            {
                foreach (var encryptionCertificate in EncryptionCertificates)
                {
                    yield return KeyDescriptor(encryptionCertificate, Saml2MetadataConstants.KeyTypes.Encryption);
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
            var signingKeyDescriptorElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.KeyDescriptor}'][contains(@use,'{Saml2MetadataConstants.KeyTypes.Signing}') or not(@use)]");
            if (signingKeyDescriptorElements != null)
            {
                SigningCertificates = ReadKeyDescriptorElements(signingKeyDescriptorElements);
            }

            var encryptionKeyDescriptorElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.KeyDescriptor}'][contains(@use,'{Saml2MetadataConstants.KeyTypes.Encryption}') or not(@use)]");
            if (encryptionKeyDescriptorElements != null)
            {
                EncryptionCertificates = ReadKeyDescriptorElements(encryptionKeyDescriptorElements);
            }

            var singleSignOnServiceElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.SingleSignOnService}']");
            if (singleSignOnServiceElements != null)
            {
                SingleSignOnServices = ReadServices<SingleSignOnService>(singleSignOnServiceElements);
            }

            var singleLogoutServiceElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.SingleLogoutService}']");
            if (singleLogoutServiceElements != null)
            {
                SingleLogoutServices = ReadServices<SingleLogoutService>(singleLogoutServiceElements);
            }

            var nameIDFormatElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.NameIDFormat}']");
            if (nameIDFormatElements != null)
            {
                NameIDFormats = ReadNameIDFormatElements(nameIDFormatElements);
            }

            return this;
        }

        private IEnumerable<X509Certificate2> ReadKeyDescriptorElements(XmlNodeList keyDescriptorElements)
        {
            foreach (XmlElement keyDescriptorElement in keyDescriptorElements)
            {
                var keyInfoElement = keyDescriptorElement.SelectSingleNode($"*[local-name()='{Saml2MetadataConstants.Message.KeyInfo}']") as XmlElement;
                if (keyInfoElement != null)
                {
                    var keyInfo = new KeyInfo();
                    keyInfo.LoadXml(keyInfoElement);
                    var keyInfoEnumerator = keyInfo.GetEnumerator();
                    while (keyInfoEnumerator.MoveNext())
                    {
                        var keyInfoX509Data = keyInfoEnumerator.Current as KeyInfoX509Data;
                        if (keyInfoX509Data != null)
                        {
                            foreach (var certificate in keyInfoX509Data.Certificates)
                            {
                                if (certificate is X509Certificate2)
                                {
                                    yield return certificate as X509Certificate2;
                                }
                            }
                        }
                    }
                }
            }
        }

        private IEnumerable<Uri> ReadNameIDFormatElements(XmlNodeList nameIDFormatElements)
        {
            foreach (XmlNode nameIDFormatElement in nameIDFormatElements)
            {
                yield return new Uri(nameIDFormatElement.InnerText);
            }
        }

        private IEnumerable<T> ReadServices<T>(XmlNodeList singleLogoutServiceElements) where T : EndpointType, new()
        {
            foreach (XmlNode singleLogoutServiceElement in singleLogoutServiceElements)
            {
                yield return new T
                {
                    Binding = singleLogoutServiceElement.Attributes[Saml2MetadataConstants.Message.Binding].GetValueOrNull<Uri>(),
                    Location = singleLogoutServiceElement.Attributes[Saml2MetadataConstants.Message.Location].GetValueOrNull<Uri>(),
                    ResponseLocation = singleLogoutServiceElement.Attributes[Saml2MetadataConstants.Message.ResponseLocation].GetValueOrNull<Uri>()
                };
            }
        }
    }
}
