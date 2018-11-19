using ITfoxtec.Identity.Saml2.Claims;
using Schemas = ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
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
    /// Saml2 Logout Request.
    /// </summary>
    public class Saml2LogoutRequest : Saml2Request
    {
        const string elementName = Schemas.Saml2Constants.Message.LogoutRequest;

        /// <summary>
        /// [Optional]
        /// The time at which the request expires, after which the recipient may discard the message. The time
        /// value is encoded in UTC, as described in Section 1.3.3.
        /// </summary>
        public DateTimeOffset? NotOnOrAfter { get; set; }

        /// <summary>
        /// [Optional]
        /// An indication of the reason for the logout, in the form of a URI reference.
        /// </summary>
        public Uri Reason { get; set; }        

        public Saml2LogoutRequest(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleLogoutDestination;
            NotOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(10);
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
            var envelope = new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            if (NotOnOrAfter.HasValue)
            {
                yield return new XAttribute(Schemas.Saml2Constants.Message.NotOnOrAfter, NotOnOrAfter.Value.UtcDateTime.ToString("o", CultureInfo.InvariantCulture));
            }

            if (Reason != null)
            {
                yield return new XAttribute(Schemas.Saml2Constants.Message.Reason, Reason.OriginalString);
            }

            if (NameId != null)
            {
                object[] nameIdContent;
                if (NameId.Format != null)
                {
                    nameIdContent = new object[] { NameId.Value, new XAttribute(Schemas.Saml2Constants.Message.Format, NameId.Format) };
                }
                else
                {
                    nameIdContent = new object[] { NameId.Value };
                }
                yield return new XElement(Schemas.Saml2Constants.AssertionNamespaceX + Schemas.Saml2Constants.Message.NameId, nameIdContent);
            }

            if (SessionIndex != null)
            {
                yield return new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + Schemas.Saml2Constants.Message.SessionIndex, SessionIndex);
            }
        }

        protected internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, validateXmlSignature);

            NameId = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.NameId, Schemas.Saml2Constants.AssertionNamespace.OriginalString].GetValueOrNull<Saml2NameIdentifier>();

            SessionIndex = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.SessionIndex, Schemas.Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
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
