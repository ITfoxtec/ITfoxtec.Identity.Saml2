using ITfoxtec.Identity.Saml2.Claims;
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
        public override string ElementName => Schemas.Saml2Constants.Message.LogoutRequest;

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
                var nameIdFormat = ReadClaimValue(identity, Saml2ClaimTypes.NameIdFormat, false);
                if (string.IsNullOrEmpty(nameIdFormat)) 
                {
                    NameId = new Saml2NameIdentifier(ReadClaimValue(identity, Saml2ClaimTypes.NameId));
                }
                else
                {
                    NameId = new Saml2NameIdentifier(ReadClaimValue(identity, Saml2ClaimTypes.NameId), new Uri(nameIdFormat));

                }
                var nameIdNameQualifier = ReadClaimValue(identity, Saml2ClaimTypes.NameQualifier, false);
                if (!string.IsNullOrEmpty(nameIdNameQualifier))
                {
                    NameId.NameQualifier = nameIdNameQualifier;
                }
                var nameIdSPNameQualifier = ReadClaimValue(identity, Saml2ClaimTypes.SPNameQualifier, false);
                if (!string.IsNullOrEmpty(nameIdSPNameQualifier))
                {
                    NameId.SPNameQualifier = nameIdSPNameQualifier;
                }
                SessionIndex = ReadClaimValue(identity, Saml2ClaimTypes.SessionIndex, false);
            }
        }

        private static string ReadClaimValue(ClaimsIdentity identity, string claimType, bool required = true)
        {
            var claim = identity.Claims.FirstOrDefault(c => c.Type == claimType);
            if (claim == null)
            {
                if (required)
                {
                    throw new InvalidOperationException($"Claim Type '{claimType}' is required to do logout.");
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
            var envelope = new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + ElementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            if (NotOnOrAfter.HasValue)
            {
                yield return new XAttribute(Schemas.Saml2Constants.Message.NotOnOrAfter, NotOnOrAfter.Value.UtcDateTime.ToString(Schemas.Saml2Constants.DateTimeFormat, CultureInfo.InvariantCulture));
            }

            if (Reason != null)
            {
                yield return new XAttribute(Schemas.Saml2Constants.Message.Reason, Reason.OriginalString);
            }

            if (NameId != null)
            {
                var nameIdContent = new List<object>() { NameId.Value };
                if (NameId.Format != null)
                {
                    nameIdContent.Add(new XAttribute(Schemas.Saml2Constants.Message.Format, NameId.Format));
                }
                if (NameId.NameQualifier != null)
                {
                    nameIdContent.Add(new XAttribute(Schemas.Saml2Constants.Message.NameQualifier, NameId.NameQualifier));
                }
                if (NameId.SPNameQualifier != null)
                {
                    nameIdContent.Add(new XAttribute(Schemas.Saml2Constants.Message.SpNameQualifier, NameId.SPNameQualifier));
                }

                yield return new XElement(Schemas.Saml2Constants.AssertionNamespaceX + Schemas.Saml2Constants.Message.NameId, nameIdContent);
            }

            if (SessionIndex != null)
            {
                yield return new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + Schemas.Saml2Constants.Message.SessionIndex, SessionIndex);
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            NameId = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.NameId, Schemas.Saml2Constants.AssertionNamespace.OriginalString].GetValueOrNull<Saml2NameIdentifier>();
            if(NameId != null)
            {
                NameId.NameQualifier = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.NameId, Schemas.Saml2Constants.AssertionNamespace.OriginalString].GetAttribute(Schemas.Saml2Constants.Message.NameQualifier);
                NameId.SPNameQualifier = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.NameId, Schemas.Saml2Constants.AssertionNamespace.OriginalString].GetAttribute(Schemas.Saml2Constants.Message.SpNameQualifier);
            }

            SessionIndex = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.SessionIndex, Schemas.Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new Saml2RequestException("Not a SAML2 Logout Request.");
            }
        }
    }
}
