using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Extension methods for XElement
    /// </summary>
    internal static class XElementExtensions
    {
        internal static XmlDocument ToXmlDocument(this XElement xElement)
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.XmlResolver = null;
            xmlDocument.PreserveWhitespace = true;
            using (var reader = xElement.CreateReader())
            {
                reader.Settings.DtdProcessing = DtdProcessing.Prohibit;
                reader.Settings.XmlResolver = null;
                xmlDocument.Load(reader);
            }
            return xmlDocument;
        }
    }
}
