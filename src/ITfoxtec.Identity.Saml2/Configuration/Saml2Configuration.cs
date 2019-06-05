using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// SAML2 component configuration
    /// </summary>
    public class Saml2Configuration
    {
        public string Issuer { get; set; }

        public Uri SingleSignOnDestination { get; set; }

        public Uri SingleLogoutDestination { get; set; }

        public string SignatureAlgorithm { get; set; } = Saml2SecurityAlgorithms.RsaSha256Signature;
        
        public X509Certificate2 SigningCertificate { get; set; }
        public X509Certificate2 DecryptionCertificate { get; set; }

        public List<X509Certificate2> SignatureValidationCertificates { get; protected set; } = new List<X509Certificate2>();
        public X509CertificateValidationMode CertificateValidationMode { get; set; } = X509CertificateValidationMode.ChainTrust;
        public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

        public bool SaveBootstrapContext { get; set; } = false;

        public bool DetectReplayedTokens { get; set; } = false;

        public bool AudienceRestricted { get; set; } = true;
        public List<string> AllowedAudienceUris { get; protected set; } = new List<string>();

        public bool SignAuthnRequest { get; set; } = false;
    }
}
