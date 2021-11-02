using System;
using System.Linq;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// This extension point contains optional protocol message extension XML elements that are agreed on between 
    /// the communicating parties.
    /// </summary>
    public class Extensions
    {
        const string elementName = Saml2Constants.Message.Extensions;
        XElement envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

        /// <summary>
        /// Add extension data to the extension XML elements.
        /// SAML extension elements MUST be namespace-qualified in a non-SAML-defined namespace.
        /// </summary>
        public XElement Element
        {
            get
            {
                return envelope;
            }
            internal set
            {
                envelope = value;
            }
        }

        public XElement ToXElement()
        {
            if (!envelope.Name.Namespace.Equals(Saml2Constants.ProtocolNamespaceX))
            {
                throw new Exception($"Invalid Extensions namespace. Required namespace '{Saml2Constants.ProtocolNamespaceX}'.");
            }
            if (!envelope.Name.LocalName.Equals(elementName))
            {
                throw new Exception($"Invalid Extensions name. Required name '{elementName}'.");
            }

            if (envelope.Elements().Count() <= 0)
            {
                throw new Exception($"Extensions is empty.");
            }

            return envelope;
        }
    }
}
