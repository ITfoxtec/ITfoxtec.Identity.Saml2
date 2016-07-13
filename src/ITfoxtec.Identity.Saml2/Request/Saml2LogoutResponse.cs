using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Logout Response.
    /// </summary>
    public class Saml2LogoutResponse : Saml2Response
    {
        const string elementName = Saml2Constants.Message.LogoutResponse;

        /// <summary>
        /// The InResponseTo as string.
        /// </summary>
        /// <value>The InResponseTo string.</value>
        public string InResponseToAsString
        {
            get { return InResponseTo.Value; }
            set { InResponseTo = new Saml2Id(value); }
        }

        public Saml2LogoutResponse(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleLogoutDestination;
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2RequestException("Not a SAML2 Logout Response.");
            }
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            //envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        //protected override IEnumerable<XObject> GetXContent()
        //{
        //}

        protected internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, validateXmlSignature);

            SessionIndex = XmlDocument.DocumentElement[Saml2Constants.Message.SessionIndex, Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }
    }
}
