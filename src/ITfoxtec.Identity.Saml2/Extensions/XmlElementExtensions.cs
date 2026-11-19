using ITfoxtec.Identity.Saml2.Util;
using System.Linq;
using System.Xml;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Extension methods for XmlElement
    /// </summary>
    internal static class XmlElementExtensions
    {
        private const string XmlnsPrefix = "xmlns";

        internal static XmlElement GetRequiredChild(this XmlElement parent, string localName, string namespaceUri, string errorMessage = null)
        {
            var children = parent.ChildNodes.OfType<XmlElement>()
                .Where(child => child.LocalName == localName && child.NamespaceURI == namespaceUri)
                .Take(2)
                .ToList();
            if (children.Count != 1)
            {
                throw new Saml2RequestException(errorMessage ?? $"Expected exactly one {localName} element in namespace '{namespaceUri}' directly under {parent.LocalName}.");
            }
            return children[0];
        }

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
