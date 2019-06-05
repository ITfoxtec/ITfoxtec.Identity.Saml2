using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The <Subject> element specifies the principal that is the subject of all of the (zero or more) statements in the assertion.
    /// </summary>
    public class Subject
    {
        const string elementName = Saml2Constants.Message.Subject;

        /// <summary>
        /// Contains an identifier.
        /// </summary>
        public NameID NameID { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (NameID != null)
            {
                yield return NameID.ToXElement();
            }
        }
    }
}
