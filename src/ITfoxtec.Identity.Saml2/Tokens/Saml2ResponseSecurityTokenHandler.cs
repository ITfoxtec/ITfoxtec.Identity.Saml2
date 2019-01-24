using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.Configuration;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;
#if NETFULL
using System;
using System.IO;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2.Tokens
{
    public class Saml2ResponseSecurityTokenHandler : Saml2SecurityTokenHandler
    {
#if !NETFULL
        public TokenValidationParameters TokenValidationParameters { get; protected set; }
#endif

        public static Saml2ResponseSecurityTokenHandler GetSaml2SecurityTokenHandler(Saml2IdentityConfiguration configuration)
        {
            var handler = new Saml2ResponseSecurityTokenHandler();
#if NETFULL
            handler.Configuration = new SecurityTokenHandlerConfiguration
            {
                SaveBootstrapContext = configuration.SaveBootstrapContext,
                AudienceRestriction = configuration.AudienceRestriction,
                IssuerNameRegistry = configuration.IssuerNameRegistry,
                CertificateValidationMode = configuration.CertificateValidationMode,
                RevocationMode = configuration.RevocationMode,
                CertificateValidator = configuration.CertificateValidator,
                DetectReplayedTokens = configuration.DetectReplayedTokens,
            };

            handler.SamlSecurityTokenRequirement.NameClaimType = ClaimTypes.NameIdentifier;
#else
            handler.TokenValidationParameters = configuration;
#endif
            return handler;
        }

#if NETFULL
        public ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token, Saml2Response saml2Response)
#else
        public ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token, string tokenString, Saml2Response saml2Response)
#endif
        {
            var saml2SecurityToken = token as Saml2SecurityToken;
            
#if NETFULL
            ValidateConditions(saml2SecurityToken.Assertion.Conditions, SamlSecurityTokenRequirement.ShouldEnforceAudienceRestriction(Configuration.AudienceRestriction.AudienceMode, saml2SecurityToken));
#else
            ValidateConditions(saml2SecurityToken, TokenValidationParameters);
#endif

#if NETFULL
            if (Configuration.DetectReplayedTokens)
            {
                DetectReplayedToken(saml2SecurityToken);
            }
#else
            if (TokenValidationParameters.ValidateTokenReplay)
            {
                ValidateTokenReplay(saml2SecurityToken.Assertion.Conditions.NotBefore, tokenString, TokenValidationParameters);
            }
#endif

#if NETFULL
            var identity = CreateClaims(saml2SecurityToken);
#else
            var identity = CreateClaimsIdentity(saml2SecurityToken, TokenValidationParameters.ValidIssuer, TokenValidationParameters);
#endif
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

#if NETFULL
            if (Configuration.SaveBootstrapContext)
            {
                identity.BootstrapContext = new BootstrapContext(saml2SecurityToken, this);
            }
#else
            if (TokenValidationParameters.SaveSigninToken)
            {
                identity.BootstrapContext = tokenString;
            }
#endif

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
