﻿using System.Collections.Generic;
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
        public override string ElementName => Saml2Constants.Message.AuthnRequest;        

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
        /// Indirectly identifies the location to which the <Response> message should be returned to the
        /// requester.It applies only to profiles in which the requester is different from the presenter, such as the
        /// Web Browser SSO profile in [SAMLProf]. The identity provider MUST have a trusted means to map
        /// the index value in the attribute to a location associated with the requester. [SAMLMeta] provides one
        /// possible mechanism.If omitted, then the identity provider MUST return the<Response> message to
        /// the default location associated with the requester for the profile of use.If the index specified is invalid,
        /// then the identity provider MAY return an error <Response> or it MAY use the default location.This
        /// attribute is mutually exclusive with the AssertionConsumerServiceURL and ProtocolBinding
        /// attributes.
        /// </summary>
        public int? AssertionConsumerServiceIndex { get; set; }

        /// <summary>
        /// [Optional]
        /// Specifies by value the location to which the &lt;Response&gt; message MUST be returned to the
        /// requester. The responder MUST ensure by some means that the value specified is in fact associated
        /// with the requester. [SAMLMeta] provides one possible mechanism; signing the enclosing
        /// &lt;AuthnRequest&gt; message is another. This attribute is mutually exclusive with the
        /// AssertionConsumerServiceIndex attribute and is typically accompanied by the
        /// ProtocolBinding attribute.
        /// </summary>
        public Uri AssertionConsumerServiceUrl { get; set; }

        /// <summary>
        /// [Optional]
        /// Indirectly identifies information associated with the requester describing the SAML attributes the
        /// requester desires or requires to be supplied by the identity provider in the<Response> message.The
        /// identity provider MUST have a trusted means to map the index value in the attribute to information
        /// associated with the requester. [SAMLMeta] provides one possible mechanism. The identity provider
        /// MAY use this information to populate one or more <saml:AttributeStatement> elements in the
        /// assertion(s) it returns.
        /// </summary>
        public int? AttributeConsumingServiceIndex { get; set; }

        /// <summary>
        /// [Optional]
        /// A URI reference that identifies a SAML protocol binding to be used when returning the &lt;Response&gt; 
        /// message. See[SAMLBind] for more information about protocol bindings and URI references defined 
        /// for them. This attribute is mutually exclusive with the AssertionConsumerServiceIndex attribute
        /// and is typically accompanied by the AssertionConsumerServiceURL attribute.
        /// </summary>
        public Uri ProtocolBinding { get; set; }

        /// <summary>
        /// [Optional]
        /// If present, specifies a filter for possible responses. Such a query asks the question "What assertions
        /// containing authentication statements do you have for this subject that satisfy the authentication
        /// context requirements in this element?"
        /// In response to an authentication query, a SAML authority returns assertions with authentication
        /// statements as follows:
        /// • Rules given in Section 3.3.4 for matching against the &lt;Subject&gt; element of the query identify the
        ///   assertions that may be returned.
        /// • If the SessionIndex attribute is present in the query, at least one &lt;AuthnStatement&gt; element in
        ///   the set of returned assertions MUST contain a SessionIndex attribute that matches the
        ///   SessionIndex attribute in the query. It is OPTIONAL for the complete set of all such matching
        ///   assertions to be returned in the response.
        /// • If the &lt;RequestedAuthnContext&gt; element is present in the query, at least one
        ///   &lt;AuthnStatement&gt; element in the set of returned assertions MUST contain an
        ///   &lt;AuthnContext&gt; element that satisfies the element in the query (see Section 3.3.2.2.1). It is
        ///   OPTIONAL for the complete set of all such matching assertions to be returned in the response.
        /// </summary>
        public RequestedAuthnContext RequestedAuthnContext { get; set; }

        /// <summary>
        /// [Optional]
        /// If present, specifies an Audience
        /// Part of the OIOSAML standard used for conditions on request.
        /// </summary>
        public Condition Conditions { get; set; }

        public Saml2AuthnRequest(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleSignOnDestination;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + ElementName);

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

            if (AssertionConsumerServiceIndex != null)
            {
                yield return new XAttribute(Saml2Constants.Message.AssertionConsumerServiceIndex, AssertionConsumerServiceIndex);
            }

            if (AssertionConsumerServiceUrl != null)
            {
                yield return new XAttribute(Saml2Constants.Message.AssertionConsumerServiceURL, AssertionConsumerServiceUrl);
            }
            if (AttributeConsumingServiceIndex != null)
            {
                yield return new XAttribute(Saml2Constants.Message.AttributeConsumingServiceIndex, AttributeConsumingServiceIndex);
            }

            if (ProtocolBinding != null)
            {
                yield return new XAttribute(Saml2Constants.Message.ProtocolBinding, ProtocolBinding);
            }

            if (Conditions != null)
            {
                yield return Conditions.ToXElement();
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

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            ForceAuthn = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.ForceAuthn].GetValueOrNull<bool>();

            IsPassive = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.IsPassive].GetValueOrNull<bool>();

            AssertionConsumerServiceIndex = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.AssertionConsumerServiceIndex].GetValueOrNull<int?>();

            AssertionConsumerServiceUrl = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.AssertionConsumerServiceURL].GetValueOrNull<Uri>();

            AttributeConsumingServiceIndex = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.AttributeConsumingServiceIndex].GetValueOrNull<int?>();

            ProtocolBinding = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.ProtocolBinding].GetValueOrNull<Uri>();

            Subject = XmlDocument.DocumentElement[Saml2Constants.Message.Subject, Saml2Constants.AssertionNamespace.OriginalString].GetElementOrNull<Subject>();

            NameIdPolicy = XmlDocument.DocumentElement[Saml2Constants.Message.NameIdPolicy, Saml2Constants.ProtocolNamespace.OriginalString].GetElementOrNull<NameIdPolicy>();

            RequestedAuthnContext = XmlDocument.DocumentElement[Saml2Constants.Message.RequestedAuthnContext, Saml2Constants.ProtocolNamespace.OriginalString].GetElementOrNull<RequestedAuthnContext>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new Saml2RequestException("Not a SAML2 Authn Request.");
            }
        }
    }
}
