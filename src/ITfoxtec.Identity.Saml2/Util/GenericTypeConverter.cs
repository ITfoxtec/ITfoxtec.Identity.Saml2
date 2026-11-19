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
            else if (genericType == typeof(DateTimeOffset) || genericType == typeof(DateTimeOffset?))
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
                if (Enum.TryParse(value, true, out AuthnContextComparisonTypes authnContextComparisonTypes))
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
                    AuthnContextClassRef = ReadChildValues(xmlNode, Schemas.Saml2Constants.Message.AuthnContextClassRef, Schemas.Saml2Constants.AssertionNamespace),
                    Comparison = ConvertValue<AuthnContextComparisonTypes>(xmlNode.Attributes[Schemas.Saml2Constants.Message.Comparison]?.Value, xmlNode),
                });
            }
            else if (genericType == typeof(Scoping))
            {
                return GenericConvertValue<T, Scoping>(new Scoping
                {
                    // Earlier versions wrote direct RequesterID children without a namespace.
                    RequesterID = ReadChildValues(xmlNode, Schemas.Saml2Constants.Message.RequesterID, Schemas.Saml2Constants.ProtocolNamespace, allowUnqualified: true),
                });
            }
            else
            {
                throw new NotSupportedException($"Unable to convert element {genericType}.");
            }
        }

        private static IEnumerable<string> ReadChildValues(XmlNode parent, string localName, Uri namespaceUri, bool allowUnqualified = false)
        {
            foreach (XmlNode child in parent.ChildNodes)
            {
                if (child is XmlElement && child.LocalName == localName &&
                    (child.NamespaceURI == namespaceUri.OriginalString || (allowUnqualified && child.NamespaceURI.Length == 0)))
                {
                    var value = child.InnerText.Trim();
                    if (value.Length > 0)
                    {
                        yield return value;
                    }
                }
            }
        }

        static T GenericConvertValue<T, U>(U value)
        {
            var type = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
            if (type == typeof(bool) && value is string stringValue)
            {
                if (stringValue == "0") return (T)(object)false;
                if (stringValue == "1") return (T)(object)true;
            }
            return (T)(value == null ? null : Convert.ChangeType(value, type));
        }

        static T? GenericConvertValueToNullable<T>(string value) where T : struct
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }
            else
            {
                if (typeof(T) == typeof(bool))
                {
                    if (value == "0") return (T?)(object)false;
                    if (value == "1") return (T?)(object)true;
                }
                return (T)Convert.ChangeType(value, typeof(T));
            }
        }
    }
}
