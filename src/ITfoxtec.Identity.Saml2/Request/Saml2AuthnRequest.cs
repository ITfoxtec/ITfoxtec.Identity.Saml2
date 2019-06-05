using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas;
using System;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Authn Request.
    /// </summary>
    public class Saml2AuthnRequest : Saml2Request
    {
        const string elementName = Saml2Constants.Message.AuthnRequest;

        ///<summary>
        /// [Optional]
        /// A Boolean value. If "true", the identity provider MUST authenticate the presenter directly rather than
        /// rely on a previous security context. If a value is not provided, the default is "false". However, if both
        /// ForceAuthn and IsPassive are "true", the identity provider MUST NOT freshly authenticate the
        /// presenter unless the constraints of IsPassive can be met.
        ///</summary>
        public bool? ForceAuthn { get; set; }

        ///<summary>
        /// [Optional]
        /// A Boolean value. If "true", the identity provider and the user agent itself MUST NOT visibly take control
        /// of the user interface from the requester and interact with the presenter in a noticeable fashion. If a
        /// value is not provided, the default is "false".
        ///</summary>
        public bool? IsPassive { get; set; }

        /// <summary>
            /// [Optional]
        /// Specifies the requested subject of the resulting assertion(s). 
        /// </summary>
        public Subject Subject { get; set; }

        /// <summary>
        /// [Optional]
        /// Specifies constraints on the name identifier to be used to represent the requested subject. If omitted,
        /// then any type of identifier supported by the identity provider for the requested subject can be used,
        /// constrained by any relevant deployment-specific policies, with respect to privacy, for example.
        /// </summary>
        public NameIdPolicy NameIdPolicy { get; set; }

        /// <summary>
        /// [Optional]
        /// Specifies by value the location to which the <Response> message MUST be returned to the
        /// requester. The responder MUST ensure by some means that the value specified is in fact associated
        /// with the requester. [SAMLMeta] provides one possible mechanism; signing the enclosing
        /// <AuthnRequest> message is another. This attribute is mutually exclusive with the
        /// AssertionConsumerServiceIndex attribute and is typically accompanied by the
        /// ProtocolBinding attribute.
        /// </summary>
        public Uri AssertionConsumerServiceUrl { get; set; }

        /// <summary>
        /// [Optional]
        /// If present, specifies a filter for possible responses. Such a query asks the question "What assertions
        /// containing authentication statements do you have for this subject that satisfy the authentication
        /// context requirements in this element?"
        /// In response to an authentication query, a SAML authority returns assertions with authentication
        /// statements as follows:
        /// • Rules given in Section 3.3.4 for matching against the <Subject> element of the query identify the
        ///   assertions that may be returned.
        /// • If the SessionIndex attribute is present in the query, at least one <AuthnStatement> element in
        ///   the set of returned assertions MUST contain a SessionIndex attribute that matches the
        ///   SessionIndex attribute in the query. It is OPTIONAL for the complete set of all such matching
        ///   assertions to be returned in the response.
        /// • If the <RequestedAuthnContext> element is present in the query, at least one
        ///   <AuthnStatement> element in the set of returned assertions MUST contain an
        ///   <AuthnContext> element that satisfies the element in the query (see Section 3.3.2.2.1). It is
        ///   OPTIONAL for the complete set of all such matching assertions to be returned in the response.
        /// </summary>
        public RequestedAuthnContext RequestedAuthnContext { get; set; }

        public Saml2AuthnRequest(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleSignOnDestination;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            if (ForceAuthn.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.ForceAuthn, ForceAuthn);
            }

            if (IsPassive.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.IsPassive, IsPassive);
            }

            if (AssertionConsumerServiceUrl != null)
            {
                yield return new XAttribute(Saml2Constants.Message.AssertionConsumerServiceURL, AssertionConsumerServiceUrl);
            }

            if (Subject != null)
            {
                yield return Subject.ToXElement();
            }

            if (NameIdPolicy != null)
            {
                yield return NameIdPolicy.ToXElement();
            }

            if (RequestedAuthnContext != null)
            {
                yield return RequestedAuthnContext.ToXElement();
            }
        }

        protected internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, validateXmlSignature);

            ForceAuthn = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.ForceAuthn].GetValueOrNull<bool>();

            IsPassive = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.IsPassive].GetValueOrNull<bool>();

            Subject = XmlDocument.DocumentElement[Saml2Constants.Message.Subject, Saml2Constants.AssertionNamespace.OriginalString].GetValueOrNull<Subject>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2RequestException("Not a SAML2 Authn Request.");
            }
        }
    }
}
