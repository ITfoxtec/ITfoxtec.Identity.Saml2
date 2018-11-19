using ITfoxtec.Identity.Saml2.Schemas;
using System.Collections.Generic;
using System.Linq;

namespace ITfoxtec.Identity.Saml2.Util
{
    internal static class Saml2StatusCodeUtil
    {
        static readonly IDictionary<string, Saml2StatusCodes> toEnums = new Dictionary<string, Saml2StatusCodes>()
        {
            { "urn:oasis:names:tc:SAML:2.0:status:Success", Saml2StatusCodes.Success },
            { "urn:oasis:names:tc:SAML:2.0:status:Requester", Saml2StatusCodes.Requester },
            { "urn:oasis:names:tc:SAML:2.0:status:Responder", Saml2StatusCodes.Responder },
            { "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch", Saml2StatusCodes.VersionMismatch },
            { "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", Saml2StatusCodes.AuthnFailed },
            { "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue", Saml2StatusCodes.InvalidAttrNameOrValue },
            { "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy", Saml2StatusCodes.InvalidNameIdPolicy },
            { "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext", Saml2StatusCodes.NoAuthnContext },
            { "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP", Saml2StatusCodes.NoAvailableIDP },
            { "urn:oasis:names:tc:SAML:2.0:status:NoPassive", Saml2StatusCodes.NoPassive },
            { "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP", Saml2StatusCodes.NoSupportedIDP },
            { "urn:oasis:names:tc:SAML:2.0:status:PartialLogout", Saml2StatusCodes.PartialLogout },
            { "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded", Saml2StatusCodes.ProxyCountExceeded },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestDenied", Saml2StatusCodes.RequestDenied },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported", Saml2StatusCodes.RequestUnsupported },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated", Saml2StatusCodes.RequestVersionDeprecated },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh", Saml2StatusCodes.RequestVersionTooHigh },
            { "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow", Saml2StatusCodes.RequestVersionTooLow },
            { "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized", Saml2StatusCodes.ResourceNotRecognized },
            { "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses", Saml2StatusCodes.TooManyResponses },
            { "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile", Saml2StatusCodes.UnknownAttrProfile },
            { "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal", Saml2StatusCodes.UnknownPrincipal },
            { "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding", Saml2StatusCodes.UnsupportedBinding },
        };

        static readonly IDictionary<Saml2StatusCodes, string> toStrings = toEnums.ToDictionary(kvp => kvp.Value, kvp => kvp.Key);

        public static Saml2StatusCodes ToEnum(string value)
        {
            return toEnums[value];
        }

        public static string ToString(Saml2StatusCodes value)
        {
            return toStrings[value];
        }
    }
}
