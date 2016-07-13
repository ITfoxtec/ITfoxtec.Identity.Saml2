using ITfoxtec.Identity.Saml2.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;

namespace ITfoxtec.Identity.Saml2.Configuration
{
    internal static class Saml2IdentityConfiguration
    {
        internal static IdentityConfiguration GetIdentityConfiguration(Saml2Configuration config)
        {
            var identityConfiguration = new IdentityConfiguration
            {
                SaveBootstrapContext = config.SaveBootstrapContext,
                AudienceRestriction = GetAudienceRestriction(config.AudienceRestricted, config.AllowedAudienceUris),
                IssuerNameRegistry = new Saml2ResponseIssuerNameRegistry(),
                CertificateValidationMode = config.CertificateValidationMode,
                RevocationMode = config.RevocationMode,
            };
            identityConfiguration.Initialize();
            return identityConfiguration;
        }

        private static AudienceRestriction GetAudienceRestriction(bool audienceRestricted, IEnumerable<Uri> allowedAudienceUris)
        {
            var audienceRestriction = new AudienceRestriction(audienceRestricted ? System.IdentityModel.Selectors.AudienceUriMode.Always : System.IdentityModel.Selectors.AudienceUriMode.Never);
            if (audienceRestricted)
            {
                foreach (var audienceUri in allowedAudienceUris)
                {
                    audienceRestriction.AllowedAudienceUris.Add(audienceUri);
                }
            }
            return audienceRestriction;
        }
    }
}
