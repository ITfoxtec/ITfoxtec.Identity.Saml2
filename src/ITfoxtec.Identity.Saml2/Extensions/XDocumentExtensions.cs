using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Extension methods for XDocument
    /// </summary>
    internal static class XDocumentExtensions
    {
        /// <summary>
        /// Converts an XDocument to an XmlDocument.
        /// </summary>
        internal static XmlDocument ToXmlDocument(this XDocument xDocument)
        {
            var xmlDocument = new XmlDocument();
            xmlDocument.XmlResolver = null;
            xmlDocument.PreserveWhitespace = true;
            using (var reader = xDocument.CreateReader())
            {
                reader.Settings.DtdProcessing = DtdProcessing.Prohibit;
                reader.Settings.XmlResolver = null;
                xmlDocument.Load(reader);
            }
            return xmlDocument;
        }

    }
}
