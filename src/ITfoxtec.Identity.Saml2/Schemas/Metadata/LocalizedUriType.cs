using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The LocalizedUri element specifies a language specific URI.
    /// </summary>
    public class LocalizedUriType
    {
        /// <param name="uri">The URI.</param>
        public LocalizedUriType(string uri)
        {
            Uri = uri;
        }

        /// <param name="uri">The URI.</param>
        public LocalizedUriType(Uri uri)
        {
            Uri = uri?.OriginalString;
        }

        /// <param name="uri">The URI.</param>
        /// <param name="lang">The language.</param>
        public LocalizedUriType(string uri, string lang) : this(uri) 
        {
            Lang = lang;
        }

        /// <param name="uri">The URI.</param>
        /// <param name="lang">The language.</param>
        public LocalizedUriType(Uri uri, string lang) : this(uri)
        {
            Lang = lang;
        }

        /// <summary>
        /// The language.
        /// </summary>
        public string Lang { get; protected set; }

        /// <summary>
        /// The URI.
        /// </summary>
        public string Uri { get; protected set; }

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

            yield return new XText(Uri);
        }
    }
}