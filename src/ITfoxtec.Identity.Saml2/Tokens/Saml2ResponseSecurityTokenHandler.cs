using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.Configuration;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tokens
{
    public class Saml2ResponseSecurityTokenHandler : Saml2SecurityTokenHandler
    {
        public static Saml2ResponseSecurityTokenHandler GetSaml2SecurityTokenHandler(IdentityConfiguration identityConfiguration)
        {
            var handler = new Saml2ResponseSecurityTokenHandler();
            handler.Configuration = new SecurityTokenHandlerConfiguration
            {
                SaveBootstrapContext = identityConfiguration.SaveBootstrapContext,
                AudienceRestriction = identityConfiguration.AudienceRestriction,
                IssuerNameRegistry = identityConfiguration.IssuerNameRegistry,
                CertificateValidationMode = identityConfiguration.CertificateValidationMode,
                RevocationMode = identityConfiguration.RevocationMode,
                CertificateValidator = identityConfiguration.CertificateValidator,
                DetectReplayedTokens = identityConfiguration.DetectReplayedTokens,
            };

            handler.SamlSecurityTokenRequirement.NameClaimType = ClaimTypes.NameIdentifier;
            return handler;
        }

        public ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token, Saml2Response saml2Response)
        {
            var saml2SecurityToken = token as Saml2SecurityToken;

            ValidateConditions(saml2SecurityToken.Assertion.Conditions, SamlSecurityTokenRequirement.ShouldEnforceAudienceRestriction(Configuration.AudienceRestriction.AudienceMode, saml2SecurityToken));

            if (Configuration.DetectReplayedTokens)
            {
                DetectReplayedToken(saml2SecurityToken);
            }

            var identity = CreateClaims(saml2SecurityToken);
            if (saml2SecurityToken.Assertion.Subject.NameId != null)
            {
                saml2Response.NameId = saml2SecurityToken.Assertion.Subject.NameId;
                identity.AddClaim(new Claim(Saml2ClaimTypes.NameId, saml2Response.NameId.Value));

                if (saml2Response.NameId.Format != null)
                {
                    identity.AddClaim(new Claim(Saml2ClaimTypes.NameIdFormat, saml2Response.NameId.Format.OriginalString));
                }
            }

            var sessionIndex = (saml2SecurityToken.Assertion.Statements.Where(s => s is Saml2AuthenticationStatement).FirstOrDefault() as Saml2AuthenticationStatement)?.SessionIndex;
            if(sessionIndex != null)
            {
                saml2Response.SessionIndex = sessionIndex;
                identity.AddClaim(new Claim(Saml2ClaimTypes.SessionIndex, saml2Response.SessionIndex));
            }

            if (Configuration.SaveBootstrapContext)
            {
                identity.BootstrapContext = new BootstrapContext(saml2SecurityToken, this);
            }            

            return new List<ClaimsIdentity>(1) { identity }.AsReadOnly();
        }

        public override string WriteToken(SecurityToken token)
        {
            var builder = new StringBuilder();
            using (var writer = XmlWriter.Create(builder))
            {
                WriteToken(writer, token);
            }
            return builder.ToString();
        }
    }
}
