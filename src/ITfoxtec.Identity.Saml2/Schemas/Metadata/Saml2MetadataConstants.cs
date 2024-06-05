using System;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    public class Saml2MetadataConstants
    {
        /// <summary>
        /// The XML namespace of the Metadata.
        /// </summary>
        internal static readonly Uri MetadataNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:metadata");

        /// <summary>
        /// The XML namespace Uri of saml assertion
        /// </summary>
        internal static readonly Uri SamlAssertionNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:assertion");
        
        /// <summary>
        /// The XML namespace of the Metadata.
        /// </summary>
        public static readonly XNamespace MetadataNamespaceX = XNamespace.Get(MetadataNamespace.OriginalString);

        /// <summary>
        /// The XML namespace Name of the Metadata.
        /// </summary>
        public static readonly XName MetadataNamespaceNameX = XNamespace.Xmlns + "m";

        /// <summary>
        /// The XML namespace of saml assertion
        /// </summary>
        public static readonly XNamespace SamlAssertionNamespaceX = XNamespace.Get(SamlAssertionNamespace.OriginalString);

        /// <summary>
        /// The XML namespace Name of the saml assertion.
        /// </summary>
        public static readonly XName SamlAssertionNamespaceNameX = XNamespace.Xmlns + "saml";
      
        /// <summary>
        /// Xsi namespace name.
        /// </summary>
        public static readonly XName XsiInstanceNamespaceNameX = XNamespace.Xmlns + "xis";

        public const string AttributeNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
        public const string AttributeNameFormatUri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

        public class Message
        {
            public const string EntityDescriptor = "EntityDescriptor";

            public const string EntitiesDescriptor = "EntitiesDescriptor";

            public const string SPSsoDescriptor = "SPSSODescriptor";

            public const string IdPSsoDescriptor = "IDPSSODescriptor";

            public const string Organization = "Organization";

            public const string ContactPerson = "ContactPerson";

            public const string EntityId = "entityID";
            
            public const string Id = "ID";

            public const string ValidUntil = "validUntil";
            
            public const string ContactType = "contactType";

            public const string Company = "Company";

            public const string GivenName = "GivenName";

            public const string SurName = "SurName";

            public const string EmailAddress = "EmailAddress";

            public const string TelephoneNumber = "TelephoneNumber";

            public const string KeyDescriptor = "KeyDescriptor";

            public const string EncryptionMethod = "EncryptionMethod";

            public const string Algorithm = "Algorithm";

            public const string Use = "use";

            public const string KeyInfo = "KeyInfo";

            public const string SingleLogoutService = "SingleLogoutService";

            public const string SingleSignOnService = "SingleSignOnService";        

            public const string ArtifactResolutionService = "ArtifactResolutionService";      

            public const string Binding = "Binding";

            public const string Location = "Location";

            public const string ResponseLocation = "ResponseLocation";

            public const string ProtocolSupportEnumeration = "protocolSupportEnumeration";

            public const string WantAuthnRequestsSigned = "WantAuthnRequestsSigned";

            public const string AuthnRequestsSigned = "AuthnRequestsSigned";

            public const string WantAssertionsSigned = "WantAssertionsSigned";

            public const string NameIDFormat = "NameIDFormat";

            public const string AssertionConsumerService = "AssertionConsumerService";

            public const string Index = "index";

            public const string IsDefault = "isDefault";

            public const string AttributeConsumingService = "AttributeConsumingService";

            public const string ServiceName = "ServiceName";

            public const string Lang = "lang";

            public const string RequestedAttribute = "RequestedAttribute";

            public const string Attribute = "Attribute";

            public const string AttributeValue = "AttributeValue";

            public const string Name = "Name";

            public const string NameFormat = "NameFormat";

            public const string IsRequired = "isRequired";

            public const string Type = "type";
    
            public const string FriendlyName = "FriendlyName";

            public const string OrganizationName = "OrganizationName";

            public const string OrganizationDisplayName = "OrganizationDisplayName";

            public const string OrganizationURL = "OrganizationURL";
        }

        public class KeyTypes
        {
            public const string Encryption = "encryption";

            public const string Signing = "signing";
        }
    }
}
