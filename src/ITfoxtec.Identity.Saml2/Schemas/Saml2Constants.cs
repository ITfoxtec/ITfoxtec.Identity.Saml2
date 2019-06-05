using System;
using System.IdentityModel.Tokens;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    public static class Saml2Constants
    {
        /// <summary>
        /// SAML 2.0 Authentication Type.
        /// </summary>
        public const string AuthenticationScheme = "saml2";

        /// <summary>
        /// SAML Version Number.
        /// </summary>
        public const string VersionNumber = "2.0";

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
        public static readonly XName AssertionNamespaceNameX = XNamespace.Xmlns + "saml2";

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
        public static readonly XName ProtocolNamespaceNameX = XNamespace.Xmlns + "saml2p";

        public static class Message
        {
            public const string SamlResponse = "SAMLResponse";

            public const string SamlRequest = "SAMLRequest";

            public const string RelayState = "RelayState";

            public const string Assertion = "Assertion";

            public const string Protocol = "Protocol";

            public const string AuthnRequest = "AuthnRequest";

            public const string AuthnResponse = "Response";

            public const string LogoutRequest = "LogoutRequest";

            public const string LogoutResponse = "LogoutResponse";

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

            internal const string Value = "Value";

            internal const string AssertionConsumerServiceURL = "AssertionConsumerServiceURL";

            internal const string RequestedAuthnContext = "RequestedAuthnContext";

            internal const string Comparison = "Comparison";

            internal const string AuthnContextClassRef = "AuthnContextClassRef";

            internal const string ForceAuthn = "ForceAuthn";

            internal const string IsPassive = "IsPassive";

            internal const string NameId = "NameID";

            internal const string SessionIndex = "SessionIndex";

            internal const string Format = "Format";

            internal const string NotOnOrAfter = "NotOnOrAfter";

            internal const string Reason = "Reason";
            
            internal const string NameIdPolicy = "NameIDPolicy";

            internal const string AllowCreate = "AllowCreate";

            internal const string SpNameQualifier = "SPNameQualifier";
            
            internal const string Extensions = "Extensions";

            internal const string InResponseTo = "InResponseTo";

            internal const string Conditions = "Conditions";

            internal const string AudienceRestriction = "AudienceRestriction";

            internal const string Audience = "Audience";

            internal const string Subject = "Subject";

            internal const string SubjectConfirmation = "SubjectConfirmation";

            internal const string SubjectConfirmationData = "SubjectConfirmationData";
        }
    }
}
