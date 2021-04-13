using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Conditions
{
    public class Audience
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        const string elementName = Saml2Constants.Message.Audience;

        public string Uri { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (!string.IsNullOrEmpty(Uri))
            {
                yield return new XText(Uri);
            }
        }
    }
}