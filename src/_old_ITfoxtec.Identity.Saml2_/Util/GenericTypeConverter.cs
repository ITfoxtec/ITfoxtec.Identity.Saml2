using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Util
{
    internal static class GenericTypeConverter
    {
        internal static T ConvertValue<T>(string value, XmlNode xmlNode)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return default(T);
            }

            var genericType = typeof(T);
            if (genericType == typeof(Uri))
            {
                return GenericConvertValue<T, Uri>(new Uri(value));
            }
            if (genericType == typeof(Saml2Id))
            {
                return GenericConvertValue<T, Saml2Id>(new Saml2Id(value));
            }
            if (genericType == typeof(DateTimeOffset))
            {
                return GenericConvertValue<T, DateTimeOffset>(DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal));
            }
            if(genericType == typeof(Saml2NameIdentifier))
            {
                return GenericConvertValue<T, Saml2NameIdentifier>(new Saml2NameIdentifier(value, ConvertValue<Uri>(xmlNode.Attributes[Saml2Constants.Message.Format]?.Value, xmlNode)));
            }
            else
            {
                return GenericConvertValue<T, string>(value);
            }
        }

        static T GenericConvertValue<T, U>(U value)
        {
            return (T)Convert.ChangeType(value, typeof(T));
        }
    }
}
