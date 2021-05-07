using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
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
        /// Specifying algorithms and algorithm-specific settings supported by the entity.
        /// </summary>
        public IEnumerable<EncryptionMethodType> EncryptionMethods { get; set; }        

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

        /// <summary>
        /// Configure default encryption methods used by .NET.
        /// </summary>
        public void SetDefaultEncryptionMethods()
        {
            EncryptionMethods = new[] { new EncryptionMethodType { Algorithm = EncryptedXml.XmlEncAES256Url }, new EncryptionMethodType { Algorithm = EncryptedXml.XmlEncRSAOAEPUrl } };
        }

        protected XObject KeyDescriptor(X509Certificate2 certificate, string keyType, IEnumerable<EncryptionMethodType> encryptionMethods = null)
        {
            var keyinfo = new KeyInfo();
            keyinfo.AddClause(new KeyInfoX509Data(certificate, CertificateIncludeOption));

            var keyDescriptorElement = new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.KeyDescriptor,
                new XAttribute(Saml2MetadataConstants.Message.Use, keyType),
                XElement.Parse(keyinfo.GetXml().OuterXml));

            if (keyType == Saml2MetadataConstants.KeyTypes.Encryption && encryptionMethods?.Count() > 0)
            {
                foreach(var encryptionMethod in encryptionMethods)
                {
                    keyDescriptorElement.Add(new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.EncryptionMethod,
                        new XAttribute(Saml2MetadataConstants.Message.Algorithm, encryptionMethod.Algorithm)));
                }
            }

            return keyDescriptorElement;
        }

        protected void ReadKeyDescriptors(XmlElement xmlElement)
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
        }

        protected void ReadSingleLogoutService(XmlElement xmlElement)
        {
            var singleLogoutServiceElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.SingleLogoutService}']");
            if (singleLogoutServiceElements != null)
            {
                SingleLogoutServices = ReadServices<SingleLogoutService>(singleLogoutServiceElements);
            }
        }

        protected void ReadNameIDFormat(XmlElement xmlElement)
        {
            var nameIDFormatElements = xmlElement.SelectNodes($"*[local-name()='{Saml2MetadataConstants.Message.NameIDFormat}']");
            if (nameIDFormatElements != null)
            {
                NameIDFormats = ReadNameIDFormatElements(nameIDFormatElements);
            }
        }

        protected IEnumerable<Uri> ReadNameIDFormatElements(XmlNodeList nameIDFormatElements)
        {
            foreach (XmlNode nameIDFormatElement in nameIDFormatElements)
            {
                yield return new Uri(nameIDFormatElement.InnerText);
            }
        }

        protected IEnumerable<X509Certificate2> ReadKeyDescriptorElements(XmlNodeList keyDescriptorElements)
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

        protected IEnumerable<T> ReadServices<T>(XmlNodeList serviceElements) where T : EndpointType, new()
        {
            foreach (XmlNode serviceElement in serviceElements)
            {
                yield return new T
                {
                    Binding = serviceElement.Attributes[Saml2MetadataConstants.Message.Binding].GetValueOrNull<Uri>(),
                    Location = serviceElement.Attributes[Saml2MetadataConstants.Message.Location].GetValueOrNull<Uri>(),
                    ResponseLocation = serviceElement.Attributes[Saml2MetadataConstants.Message.ResponseLocation].GetValueOrNull<Uri>()
                };
            }
        }
    }
}
