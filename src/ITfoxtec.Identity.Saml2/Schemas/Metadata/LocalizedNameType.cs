using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The LocalizedName element specifies a language specific name.
    /// </summary>
    public class LocalizedNameType
    {
        /// <param name="name">The name.</param>
        public LocalizedNameType(string name)
        {
            Name = name;
        }

        /// <param name="name">The name.</param>
        /// <param name="lang">The language.</param>
        public LocalizedNameType(string name, string lang) : this(name) 
        {
            Lang = lang;
        }

        /// <summary>
        /// The language.
        /// </summary>
        public string Lang { get; protected set; }

        /// <summary>
        /// The Name.
        /// </summary>
        public string Name { get; protected set; }

        public XElement ToXElement(XName elementName)
        {
            var envelope = new XElement(elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Lang != null)
            {
                yield return new XAttribute(XNamespace.Xml + Saml2MetadataConstants.Message.Lang, Lang);
            }

            yield return new XText(Name);
        }
    }
}