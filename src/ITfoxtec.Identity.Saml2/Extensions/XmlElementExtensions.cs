using ITfoxtec.Identity.Saml2.Util;
using System.Xml;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Extension methods for XmlElement
    /// </summary>
    internal static class XmlElementExtensions
    {
        private const string XmlnsPrefix = "xmlns";

        public static T GetValueOrNull<T>(this XmlElement xmlElement)
        {
            return GenericTypeConverter.ConvertValue<T>(xmlElement?.InnerText?.Trim(), xmlElement);
        }

        public static T GetElementOrNull<T>(this XmlElement xmlElement)
        {
            return GenericTypeConverter.ConvertElement<T>(xmlElement);
        }

        internal static XmlDocument ToXmlDocument(this XmlElement xmlElement)
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.XmlResolver = null;
            xmlDocument.PreserveWhitespace = true;
            using (var reader = xmlElement.CreateNavigator().ReadSubtree())
            {
                xmlDocument.Load(reader);
            }
            // ReadSubtree may omit inherited namespaces that are not visibly used by element names.
            // They can still be covered by an InclusiveNamespaces PrefixList in an XML signature.
            foreach (var namespaceBinding in xmlElement.CreateNavigator().GetNamespacesInScope(XmlNamespaceScope.All))
            {
                if (xmlDocument.DocumentElement.GetNamespaceOfPrefix(namespaceBinding.Key) != namespaceBinding.Value)
                {
                    xmlDocument.DocumentElement.SetAttribute(namespaceBinding.Key.Length == 0 ? XmlnsPrefix : XmlnsPrefix + ":" + namespaceBinding.Key, namespaceBinding.Value);
                }
            }
            return xmlDocument;
        }
    }
}
