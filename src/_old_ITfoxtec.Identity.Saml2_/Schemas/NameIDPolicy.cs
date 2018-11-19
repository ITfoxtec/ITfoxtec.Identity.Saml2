using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The <NameIDPolicy> element tailors the name identifier in the subjects of assertions resulting from an <AuthnRequest>.
    /// </summary>
    public class NameIdPolicy
    {
        const string elementName = Saml2Constants.Message.NameIdPolicy;

        /// <summary>
        /// A Boolean value used to indicate whether the identity provider is allowed, in the course of fulfilling the
        /// request, to create a new identifier to represent the principal. Defaults to "false". When "false", the
        /// requester constrains the identity provider to only issue an assertion to it if an acceptable identifier for
        /// the principal has already been established. Note that this does not prevent the identity provider from
        /// creating such identifiers outside the context of this specific request (for example, in advance for a
        /// large number of principals).
        /// </summary>
        public bool? AllowCreate { get; set; }

        /// <summary>
        /// Specifies the URI reference corresponding to a name identifier format defined in this or another
        /// specification (see Section 8.3 for examples). The additional value of
        /// urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted is defined specifically for use
        /// within this attribute to indicate a request that the resulting identifier be encrypted.
        /// </summary>
        public string Format { get; set; }

        /// <summary>
        /// Optionally specifies that the assertion subject's identifier be returned (or created) in the namespace of
        /// a service provider other than the requester, or in the namespace of an affiliation group of service
        /// providers. See for example the definition of urn:oasis:names:tc:SAML:2.0:nameidformat:
        /// persistent in Section 8.3.7.
        /// </summary>
        public string SPNameQualifier { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (AllowCreate.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.AllowCreate, AllowCreate);
            }

            if (!string.IsNullOrWhiteSpace(Format))
            {
                yield return new XAttribute(Saml2Constants.Message.Format, Format);
            }

            if (!string.IsNullOrWhiteSpace(SPNameQualifier))
            {
                yield return new XAttribute(Saml2Constants.Message.SpNameQualifier, SPNameQualifier);
            }
        }
    }
}
