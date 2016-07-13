using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    public class RequestedAuthnContext
    {
        const string elementName = Saml2Constants.Message.RequestedAuthnContext;

        /// <summary>
        /// [Optional]
        /// Specifies the comparison method used to evaluate the requested context classes or statements, one
        /// of "exact", "minimum", "maximum", or "better". The default is "exact".
        /// 
        /// If Comparison is set to "exact" or omitted, then the resulting authentication context in the authentication
        /// statement MUST be the exact match of at least one of the authentication contexts specified.
        /// If Comparison is set to "minimum", then the resulting authentication context in the authentication
        /// statement MUST be at least as strong (as deemed by the responder) as one of the authentication
        /// contexts specified.
        /// If Comparison is set to "better", then the resulting authentication context in the authentication
        /// statement MUST be stronger (as deemed by the responder) than any one of the authentication contexts
        /// specified.
        /// If Comparison is set to "maximum", then the resulting authentication context in the authentication
        /// statement MUST be as strong as possible (as deemed by the responder) without exceeding the strength
        /// of at least one of the authentication contexts specified.
        /// </summary>
        public AuthnContextComparisonTypes? Comparison { get; set; }

        /// <summary>
        /// [One or More]
        /// Specifies one or more URI references identifying authentication context classes or declarations.
        /// These elements are defined in Section 2.7.2.2. For more information about authentication context
        /// classes, see [SAMLAuthnCxt].
        /// </summary>
        public IEnumerable<string> AuthnContextClassRef { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (Comparison.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.Comparison, Comparison.ToString().ToLowerInvariant());
            }

            foreach (var item in AuthnContextClassRef)
            {
                yield return new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.AuthnContextClassRef, item);
            }
        }
    }
}
