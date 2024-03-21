#if !NETFULL
using Microsoft.IdentityModel.Tokens;
#endif
using System;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    public static class Saml2Constants
    {
        /// <summary>
        /// SAML 2.0 request / response max length.
        /// </summary>
#if !NETFULL
        public const int RequestResponseMaxLength = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
#else
        public const int RequestResponseMaxLength = 1024 * 250;        
#endif

        /// <summary>
        /// SAML 2.0 Authentication Type.
        /// </summary>
        public const string AuthenticationScheme = "saml2";

        /// <summary>
        /// SAML Version Number.
        /// </summary>
        public const string VersionNumber = "2.0";

        /// <summary>
        /// All SAML time values have the type xs:dateTime, which is built in to the W3C XML Schema Datatypes specification[Schema2], and MUST be expressed in UTC form, 
        /// with no time zone component.
        /// SAML system entities SHOULD NOT rely on time resolution finer than milliseconds.Implementations MUST NOT generate time instants that specify leap seconds.
        /// </summary>
        public const string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

        /// <summary>
        /// Saml2 Bearer token.
        /// </summary>
        public static readonly Uri Saml2BearerToken = new Uri("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        /// <summary>
        /// The XML namespace of the SAML2 Assertion.
        /// </summary>
        internal static readonly Uri AssertionNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:assertion");
        /// <summary>
        /// The XML namespace of the SAML2 Assertion.
        /// </summary>
        public static readonly XNamespace AssertionNamespaceX = XNamespace.Get(AssertionNamespace.OriginalString);
        /// <summary>
        /// The XML Namespace Name of the SAML2 Assertion.
        /// </summary>
        public static readonly XName AssertionNamespaceNameX = XNamespace.Xmlns + "saml";

        /// <summary>
        /// The XML namespace of the SAML2 Protocol.
        /// </summary>
        internal static readonly Uri ProtocolNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:protocol");
        /// <summary>
        /// The XML namespace of the SAML2 Protocol.
        /// </summary>
        public static readonly XNamespace ProtocolNamespaceX = XNamespace.Get(ProtocolNamespace.OriginalString);
        /// <summary>
        /// The XML Namespace Name of the SAML2 Protocol.
        /// </summary>
        public static readonly XName ProtocolNamespaceNameX = XNamespace.Xmlns + "samlp";

        /// <summary>
        /// The XML namespace of the SAML2 SOAP Envelope.
        /// </summary>
        public static readonly Uri SoapEnvironmentNamespace = new Uri("http://schemas.xmlsoap.org/soap/envelope/");
        /// <summary>
        /// The XML namespace of the SAML2 SOAP Envelope.
        /// </summary>
        public static readonly XNamespace SoapEnvironmentNamespaceX = XNamespace.Get(SoapEnvironmentNamespace.OriginalString);
        /// <summary>
        /// The XML namespace Name of the SAML2 SOAP Envelope.
        /// </summary>
        public static readonly XName SoapEnvironmentNamespaceNameX = XNamespace.Xmlns + "SOAP-ENV";

        public static class Message
        {
            public const string SamlResponse = "SAMLResponse";

            public const string SamlRequest = "SAMLRequest";

            public const string SamlArt = "SAMLart";

            public const string RelayState = "RelayState";

            public const string Assertion = "Assertion";

            public const string EncryptedAssertion = "EncryptedAssertion";

            public const string Protocol = "Protocol";

            public const string AuthnRequest = "AuthnRequest";

            public const string AuthnResponse = "Response";

            public const string LogoutRequest = "LogoutRequest";

            public const string LogoutResponse = "LogoutResponse";

            public const string ArtifactResolve = "ArtifactResolve";

            public const string ArtifactResponse = "ArtifactResponse";

            internal const string Artifact = "Artifact";

            internal const string Id = "ID";

            internal const string Version = "Version";

            internal const string IssueInstant = "IssueInstant";

            internal const string Consent = "Consent";

            internal const string Destination = "Destination";

            internal const string Signature = "Signature";

            internal const string SigAlg = "SigAlg";

            internal const string Issuer = "Issuer";

            internal const string Status = "Status";

            internal const string StatusCode = "StatusCode";

            internal const string StatusMessage = "StatusMessage";

            internal const string Value = "Value";

            internal const string AssertionConsumerServiceIndex = "AssertionConsumerServiceIndex";

            internal const string AssertionConsumerServiceURL = "AssertionConsumerServiceURL";

            internal const string AttributeConsumingServiceIndex = "AttributeConsumingServiceIndex";

            internal const string ProtocolBinding = "ProtocolBinding";

            internal const string RequestedAuthnContext = "RequestedAuthnContext";

            internal const string Comparison = "Comparison";

            internal const string AuthnContextClassRef = "AuthnContextClassRef";

            internal const string ForceAuthn = "ForceAuthn";

            internal const string IsPassive = "IsPassive";

            internal const string NameId = "NameID";

            internal const string SessionIndex = "SessionIndex";

            internal const string Format = "Format";

            internal const string NotOnOrAfter = "NotOnOrAfter";

            internal const string NotBefore = "NotBefore";

            internal const string Reason = "Reason";
            
            internal const string NameIdPolicy = "NameIDPolicy";

            internal const string AllowCreate = "AllowCreate";

            internal const string NameQualifier = "NameQualifier";

            internal const string SpNameQualifier = "SPNameQualifier";
            
            internal const string Extensions = "Extensions";

            internal const string InResponseTo = "InResponseTo";

            internal const string Conditions = "Conditions";

            internal const string AudienceRestriction = "AudienceRestriction";

            internal const string Audience = "Audience";

            internal const string Subject = "Subject";

            internal const string SubjectConfirmation = "SubjectConfirmation";

            internal const string SubjectConfirmationData = "SubjectConfirmationData";

            internal const string OneTimeUse = "OneTimeUse";

            internal const string ProxyRestriction = "ProxyRestriction";

            internal const string Count = "Count";

            internal const string Envelope = "Envelope";

            internal const string Body = "Body";

            internal const string Scoping = "Scoping";

            internal const string RequesterID = "RequesterID";

            internal const string IDPList = "IDPList";

            internal const string IDPEntry = "IDPEntry";

            internal const string ProviderID = "ProviderID";

            internal const string Name = "Name";

            internal const string Loc = "Loc";

            internal const string GetComplete = "GetComplete";
            
            internal const string ProviderName = "ProviderName";

        }
    }
}
