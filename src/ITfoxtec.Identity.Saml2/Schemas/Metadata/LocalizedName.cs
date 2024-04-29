using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The LocalizedName element specifies a language specific name.
    /// </summary>
    public class LocalizedName
    {
        public LocalizedName(string value, string lang)
        {
            Lang = lang;
            Value = value;
        }

        /// <summary>
        /// The language.
        /// </summary>
        public string Lang { get; protected set; }

        /// <summary>
        /// The text value.
        /// </summary>
        public string Value { get; protected set; }

        public XElement ToXElement(XName elementName)
        {
            var envelope = new XElement(elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(XNamespace.Xml + "lang", Lang);
            yield return new XText(Value);
        }
    }
}
