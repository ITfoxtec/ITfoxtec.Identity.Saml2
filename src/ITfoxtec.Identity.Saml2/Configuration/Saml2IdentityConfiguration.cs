using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Util;
#if NETFULL
using ITfoxtec.Identity.Saml2.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
#else
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Selectors;
#endif

namespace ITfoxtec.Identity.Saml2.Configuration
{
    public class Saml2IdentityConfiguration :
#if NETFULL
        IdentityConfiguration
#else
        TokenValidationParameters
#endif
    {

#if !NETFULL
        public X509CertificateValidator CertificateValidator { get; set; }
#endif

        public static Saml2IdentityConfiguration GetIdentityConfiguration(Saml2Configuration config)
        {
            var configuration = new Saml2IdentityConfiguration();

#if NETFULL
            configuration.SaveBootstrapContext = config.SaveBootstrapContext;
            configuration.AudienceRestriction = GetAudienceRestriction(config.AudienceRestricted, config.AllowedAudienceUris);
            configuration.IssuerNameRegistry = new Saml2ResponseIssuerNameRegistry();
            configuration.CertificateValidationMode = config.CertificateValidationMode;
            configuration.RevocationMode = config.RevocationMode;
            configuration.DetectReplayedTokens = config.DetectReplayedTokens;
            configuration.Initialize();
#else
            configuration.SaveSigninToken = config.SaveBootstrapContext;
            configuration.ValidateAudience = config.AudienceRestricted;
            configuration.ValidAudiences = config.AllowedAudienceUris.Select(a => a);
            configuration.ValidIssuer = config.Issuer;
            configuration.ValidateTokenReplay = config.DetectReplayedTokens;

            configuration.NameClaimType = ClaimTypes.NameIdentifier;

            configuration.CertificateValidator = new Saml2CertificateValidator
            {
                CertificateValidationMode = config.CertificateValidationMode,
                RevocationMode = config.RevocationMode,
            };
#endif
            return configuration;
        }

#if NETFULL
        private static AudienceRestriction GetAudienceRestriction(bool audienceRestricted, IEnumerable<string> allowedAudienceUris)
        {
            var audienceRestriction = new AudienceRestriction(audienceRestricted ? System.IdentityModel.Selectors.AudienceUriMode.Always : System.IdentityModel.Selectors.AudienceUriMode.Never);
            if (audienceRestricted)
            {
                foreach (var audienceUri in allowedAudienceUris)
                {
                    audienceRestriction.AllowedAudienceUris.Add(new Uri(audienceUri));
                }
            }
            return audienceRestriction;
        }
#endif
    }
}
