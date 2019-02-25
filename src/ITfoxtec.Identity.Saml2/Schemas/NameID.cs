using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The <NameID> is used when an element serves to represent an entity by a string-valued name.
    /// </summary>
    public class NameID
    {
        const string elementName = Saml2Constants.Message.NameId;

        /// <summary>
        /// String content containing the actual identifier.
        /// </summary>
        public string ID { get; set; }

        /// <summary>
        /// [Optional]
        /// A URI reference representing the classification of string-based identifier information. See Section
        /// 8.3 for the SAML-defined URI references that MAY be used as the value of the Format attribute
        /// and their associated descriptions and processing rules.Unless otherwise specified by an element
        /// based on this type, if no Format value is provided, then the value
        /// urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified(see Section 8.3.1) is in effect.
        /// </summary>
        public string Format { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (!string.IsNullOrWhiteSpace(Format))
            {
                yield return new XAttribute(Saml2Constants.Message.Format, Format);
            }

            yield return new XText(ID);
        }
    }
}
