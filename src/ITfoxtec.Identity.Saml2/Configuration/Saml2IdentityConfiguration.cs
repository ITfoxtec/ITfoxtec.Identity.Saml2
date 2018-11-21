using ITfoxtec.Identity.Saml2.Tokens;
using System;
using System.Collections.Generic;
#if NETFULL
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
#else
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
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
        public X509CertificateValidationMode CertificateValidationMode { get; set; }
        public X509RevocationMode RevocationMode { get; set; }
        public Saml2CertificateValidator CertificateValidator { get; set; }
        
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
            configuration.Initialize();
#else
            configuration.SaveSigninToken = config.SaveBootstrapContext;
            configuration.ValidateAudience = config.AudienceRestricted;
            configuration.ValidIssuer = config.Issuer?.OriginalString;
            configuration.CertificateValidationMode = config.CertificateValidationMode;
            configuration.RevocationMode = config.RevocationMode;
            configuration.NameClaimType = ClaimTypes.NameIdentifier;
            configuration.CertificateValidator = new Saml2CertificateValidator { IdentityConfiguration = configuration };
#endif
            return configuration;
        }

        public void ValidateCertificate(X509Certificate2 certificate)
        {
#if NETFULL
            CertificateValidator.Validate(certificate);
#else
            CertificateValidator.Validate(certificate);
#endif
        }

#if NETFULL
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
#endif
    }
}
