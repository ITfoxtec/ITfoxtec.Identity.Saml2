using ITfoxtec.Identity.Saml2.Util;
using System.Xml;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Extension methods for XmlAttribute
    /// </summary>
    internal static class XmlAttributeExtensions
    {
        public static T GetValueOrNull<T>(this XmlAttribute xmlAttribute)
        {
            return GenericTypeConverter.ConvertValue<T>(xmlAttribute?.Value, xmlAttribute);
        }
    }
}
