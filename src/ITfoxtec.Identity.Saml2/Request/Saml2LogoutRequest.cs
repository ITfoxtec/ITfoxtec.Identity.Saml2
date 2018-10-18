using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Logout Request.
    /// </summary>
    public class Saml2LogoutRequest : Saml2Request
    {
        const string elementName = Saml2Constants.Message.LogoutRequest;

        /// <summary>
        /// [Optional]
        /// The time at which the request expires, after which the recipient may discard the message. The time
        /// value is encoded in UTC, as described in Section 1.3.3.
        /// </summary>
        public DateTime? NotOnOrAfter { get; set; }

        /// <summary>
        /// [Optional]
        /// An indication of the reason for the logout, in the form of a URI reference.
        /// </summary>
        public Uri Reason { get; set; }        

        public Saml2LogoutRequest(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleLogoutDestination;
            NotOnOrAfter = DateTime.UtcNow.AddMinutes(10);
        }

        public Saml2LogoutRequest(Saml2Configuration config, ClaimsPrincipal currentPrincipal) : this(config)
        {
            var identity = currentPrincipal.Identities.First();
            if (identity.IsAuthenticated)
            {
                NameId = new Saml2NameIdentifier(ReadClaimValue(identity, Saml2ClaimTypes.NameId), new Uri(ReadClaimValue(identity, Saml2ClaimTypes.NameIdFormat, false)));
                SessionIndex = ReadClaimValue(identity, Saml2ClaimTypes.SessionIndex, false);
            }           
        }

        private static string ReadClaimValue(ClaimsIdentity identity, string claimType, bool required = true)
        {
            var claim = identity.Claims.FirstOrDefault(c => c.Type == claimType);
            if (claim == null)
            {
                if(required)
                {
                    throw new InvalidOperationException("Missing Claim Type: " + claimType);
                }
                else
                {
                    return null;
                }
            }
            return claim.Value;
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
            if (NotOnOrAfter.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.NotOnOrAfter, NotOnOrAfter.Value.ToString("o", CultureInfo.InvariantCulture));
            }

            if (Reason != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Reason, Reason.OriginalString);
            }

            if (NameId != null)
            {
                object[] nameIdContent;
                if (NameId.Format != null)
                {
                    nameIdContent = new object[] { NameId.Value, new XAttribute(Saml2Constants.Message.Format, NameId.Format) };
                }
                else
                {
                    nameIdContent = new object[] { NameId.Value };
                }

                yield return new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.NameId, nameIdContent);
            }

            if (SessionIndex != null)
            {
                yield return new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.SessionIndex, SessionIndex);
            }
        }

        protected internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, validateXmlSignature);

            NameId = XmlDocument.DocumentElement[Saml2Constants.Message.NameId, Saml2Constants.AssertionNamespace.OriginalString].GetValueOrNull<Saml2NameIdentifier>();

            SessionIndex = XmlDocument.DocumentElement[Saml2Constants.Message.SessionIndex, Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2RequestException("Not a SAML2 Logout Request.");
            }
        }
    }
}
