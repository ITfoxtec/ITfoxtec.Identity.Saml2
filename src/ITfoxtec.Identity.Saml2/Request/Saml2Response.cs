﻿using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Util;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Generic Saml2 Response.
    /// </summary>
    public abstract class Saml2Response : Saml2Request
    {
        /// <summary>
        /// [Required]
        /// A code representing the status of the corresponding request.
        /// </summary>
        public Schemas.Saml2StatusCodes Status { get; set; }

        /// <summary>
        /// [Optional]
        /// A message which MAY be returned to an operator, describing the <see cref="Status"/> of the corresponding request.
        /// </summary>
        public string StatusMessage { get; set; }

        /// <summary>
        /// [Optional]
        /// A reference to the identifier of the request to which the response corresponds, if any. If the response
        /// is not generated in response to a request, or if the ID attribute value of a request cannot be
        /// determined (for example, the request is malformed), then this attribute MUST NOT be present.
        /// Otherwise, it MUST
        /// </summary>
        public Saml2Id InResponseTo { get; set; }

        /// <summary>
        /// The InResponseTo as string.
        /// </summary>
        /// <value>The InResponseTo string.</value>
        public string InResponseToAsString
        {
            get { return InResponseTo.Value; }
            set { InResponseTo = new Saml2Id(value); }
        }

        public Saml2Response(Saml2Configuration config) : base(config)
        { }

        protected override IEnumerable<XObject> GetXContent()
        {
            foreach (var item in  base.GetXContent())
            {
                yield return item;
            }

            var statusEnvelope = new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + Schemas.Saml2Constants.Message.Status,
                new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + Schemas.Saml2Constants.Message.StatusCode,
                    new XAttribute(Schemas.Saml2Constants.Message.Value, Saml2StatusCodeUtil.ToString(Status))));

            if (!string.IsNullOrWhiteSpace(StatusMessage))
            {
                statusEnvelope.Add(new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + Schemas.Saml2Constants.Message.StatusMessage, StatusMessage));
            }

            yield return statusEnvelope;

            if (InResponseTo != null)
            {
                yield return new XAttribute(Schemas.Saml2Constants.Message.InResponseTo, InResponseToAsString);
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            InResponseTo = XmlDocument.DocumentElement.Attributes[Schemas.Saml2Constants.Message.InResponseTo].GetValueOrNull<Saml2Id>();

            ValidateStatus();
        }

        protected virtual void ValidateStatus()
        {
            Status = Saml2StatusCodeUtil.ToEnum(XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Status, Schemas.Saml2Constants.ProtocolNamespace.OriginalString][Schemas.Saml2Constants.Message.StatusCode, Schemas.Saml2Constants.ProtocolNamespace.OriginalString].Attributes[Schemas.Saml2Constants.Message.Value].GetValueOrNull<string>());

            StatusMessage = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Status, Schemas.Saml2Constants.ProtocolNamespace.OriginalString][Schemas.Saml2Constants.Message.StatusMessage, Schemas.Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }
    }
}
