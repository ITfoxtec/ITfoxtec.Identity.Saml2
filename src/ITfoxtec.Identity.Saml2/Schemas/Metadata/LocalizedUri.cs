using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The LocalizedUri element specifies a language specific URI.
    /// </summary>
    public class LocalizedUri
    {
        public LocalizedUri(Uri uri, string lang)
        {
            Lang = lang;
            Value = uri;
        }

        /// <summary>
        /// Language
        /// </summary>
        public string Lang { get; protected set; }

        /// <summary>
        /// The URI value.
        /// </summary>
        public Uri Value { get; protected set; }

        public XElement ToXElement(XName elementName)
        {
            var envelope = new XElement(elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(XNamespace.Xml + "lang", Lang);
            yield return new XText(Value.OriginalString);
        }
    }
}