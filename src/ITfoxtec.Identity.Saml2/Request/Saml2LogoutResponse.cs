﻿using System;
using System.Xml;
using System.Xml.Linq;

#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Logout Response.
    /// </summary>
    public class Saml2LogoutResponse : Saml2Response
    {
        public override string ElementName => Schemas.Saml2Constants.Message.LogoutResponse;

        public Saml2LogoutResponse(Saml2Configuration config) : base(config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            Destination = config.SingleLogoutDestination;
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new Saml2RequestException("Not a SAML2 Logout Response.");
            }
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + ElementName);

            envelope.Add(base.GetXContent());
            //envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            SessionIndex = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.SessionIndex, Schemas.Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }
    }
}
