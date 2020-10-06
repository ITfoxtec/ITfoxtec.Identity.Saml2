using Schemas = ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Globalization;
using System.Xml;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Collections.Generic;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2.Util
{
    internal static class GenericTypeConverter
    {
        internal static T ConvertValue<T>(string value, XmlNode xmlNode)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return default;
            }

            var genericType = typeof(T);
            if (genericType == typeof(Uri))
            {
                return GenericConvertValue<T, Uri>(new Uri(value));
            }
            else if (genericType == typeof(Saml2Id))
            {
                return GenericConvertValue<T, Saml2Id>(new Saml2Id(value));
            }
            else if (genericType == typeof(DateTimeOffset))
            {
                return GenericConvertValue<T, DateTimeOffset>(DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal));
            }
            else if (genericType == typeof(Saml2NameIdentifier))
            {
                return GenericConvertValue<T, Saml2NameIdentifier>(new Saml2NameIdentifier(value, ConvertValue<Uri>(xmlNode.Attributes[Schemas.Saml2Constants.Message.Format]?.Value, xmlNode)));
            }
            else if (genericType == typeof(NameID))
            {
                return GenericConvertValue<T, NameID>(new NameID { ID = value, Format = xmlNode.Attributes[Schemas.Saml2Constants.Message.Format]?.Value });
            }
            else if(genericType == typeof(AuthnContextComparisonTypes))
            {
                if (Enum.TryParse(value, out AuthnContextComparisonTypes authnContextComparisonTypes))
                {
                    return GenericConvertValue<T, AuthnContextComparisonTypes>(authnContextComparisonTypes);
                }
                else
                {
                    return default;
                }
            }
            else
            {
                return GenericConvertValue<T, string>(value);
            }
        }

        internal static T ConvertElement<T>(XmlNode xmlNode)
        {
            if (xmlNode == null)
            {
                return default;
            }

            var genericType = typeof(T);
            if (genericType == typeof(Subject))
            {
                return GenericConvertValue<T, Subject>(new Subject { NameID = ConvertValue<NameID>(xmlNode[Schemas.Saml2Constants.Message.NameId, Schemas.Saml2Constants.AssertionNamespace.OriginalString]?.InnerText?.Trim(), xmlNode) });
            }
            else if (genericType == typeof(NameIdPolicy))
            {
                return GenericConvertValue<T, NameIdPolicy>(new NameIdPolicy
                {
                    AllowCreate = GenericConvertValueToNullable<bool>(xmlNode.Attributes[Schemas.Saml2Constants.Message.AllowCreate]?.Value),
                    Format = xmlNode.Attributes[Schemas.Saml2Constants.Message.Format]?.Value,
                    SPNameQualifier = xmlNode.Attributes[Schemas.Saml2Constants.Message.SpNameQualifier]?.Value
                });
            }
            else if (genericType == typeof(RequestedAuthnContext))
            {
                return GenericConvertValue<T, RequestedAuthnContext>(new RequestedAuthnContext
                {
                    AuthnContextClassRef = GetAuthnContextClassRef(xmlNode.SelectNodes($"//*[local-name()='{Schemas.Saml2Constants.Message.AuthnContextClassRef}']")),
                    Comparison = ConvertValue<AuthnContextComparisonTypes>(xmlNode.Attributes[Schemas.Saml2Constants.Message.Comparison]?.Value, xmlNode),
                });
            }
            else
            {
                throw new NotSupportedException($"Unable to convert element {genericType}.");
            }
        }

        private static IEnumerable<string> GetAuthnContextClassRef(XmlNodeList xmlNodes)
        {
            foreach (XmlNode xmlNode in xmlNodes)
            {
                if(!string.IsNullOrWhiteSpace(xmlNode?.InnerText))
                {
                    yield return ConvertValue<string>(xmlNode?.InnerText?.Trim(), xmlNode);
                }                
            }
        }

        static T GenericConvertValue<T, U>(U value)
        {
            return (T)Convert.ChangeType(value, typeof(T));
        }

        static T? GenericConvertValueToNullable<T>(string value) where T : struct
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }
            else
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }
        }
    }
}
