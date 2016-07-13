
using System;
namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The following identifiers MAY be used in the Consent attribute defined on the RequestAbstractType and
    /// StatusResponseType complex types to communicate whether a principal gave consent, and under what
    /// conditions, for the message.
    /// </summary>
    public static class ConsentIdentifierTypes
    {
        /// <summary>
        /// No claim as to principal consent is being made.
        /// </summary>
        public static Uri Unspecified = new Uri("urn:oasis:names:tc:SAML:2.0:consent:unspecified");

        /// <summary>
        /// Indicates that a principal’s consent has been obtained by the issuer of the message.
        /// </summary>
        public static Uri Obtained = new Uri("urn:oasis:names:tc:SAML:2.0:consent:obtained");

        /// <summary>
        /// Indicates that a principal’s consent has been obtained by the issuer of the message at some point prior to
        /// the action that initiated the message.
        /// </summary>
        public static Uri Prior = new Uri("urn:oasis:names:tc:SAML:2.0:consent:prior");

        /// <summary>
        /// Indicates that a principal’s consent has been implicitly obtained by the issuer of the message during the
        /// action that initiated the message, as part of a broader indication of consent. Implicit consent is typically
        /// more proximal to the action in time and presentation than prior consent, such as part of a session of
        /// activities.
        /// </summary>
        public static Uri Implicit = new Uri("urn:oasis:names:tc:SAML:2.0:consent:current-implicit");

        /// <summary>
        /// Indicates that a principal’s consent has been explicitly obtained by the issuer of the message during the
        /// action that initiated the message.
        /// </summary>
        public static Uri Explicit = new Uri("urn:oasis:names:tc:SAML:2.0:consent:current-explicit");

        /// <summary>
        /// Indicates that the issuer of the message did not obtain consent.
        /// </summary>
        public static Uri Unavailable = new Uri("urn:oasis:names:tc:SAML:2.0:consent:unavailable");

        /// <summary>
        /// Indicates that the issuer of the message does not believe that they need to obtain or report consent.
        /// </summary>
        public static Uri Inapplicable = new Uri("urn:oasis:names:tc:SAML:2.0:consent:inapplicable");
    }
}
