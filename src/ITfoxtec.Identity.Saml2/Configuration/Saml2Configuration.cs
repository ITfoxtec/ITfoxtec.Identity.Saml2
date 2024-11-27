using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.Xml;
using System.Linq;
#if NETFULL
using System.IdentityModel.Configuration;
#else
using Microsoft.IdentityModel.Tokens;
#endif

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

        public Saml2IndexedEndpoint ArtifactResolutionService { get; set; }

        public bool ValidateArtifact { get; set; } = true;

        public string SignatureAlgorithm { get; set; } = Saml2SecurityAlgorithms.RsaSha256Signature;

        // Optionally set a canonicalization method, default "http://www.w3.org/2001/10/xml-exc-c14n#". E.g, set "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" for Amazon.
        public string XmlCanonicalizationMethod { get; set; } = SignedXml.XmlDsigExcC14NTransformUrl;        

        public X509Certificate2 SigningCertificate { get; set; }
        [Obsolete("DecryptionCertificate are obsolete to support multiple decryption certificates. Use DecryptionCertificates instead.")]
        public X509Certificate2 DecryptionCertificate
        {
            get { return DecryptionCertificates?.FirstOrDefault(); }
            set { DecryptionCertificates = new List<X509Certificate2> { value }; }
        }
        public List<X509Certificate2> DecryptionCertificates { get; set; } = new List<X509Certificate2>();
        /// <summary>
        /// If set the authn responses created by the library is encrypt.
        /// </summary>
        public X509Certificate2 EncryptionCertificate { get; set; }

        public string AllowedIssuer { get; set; }

        public List<X509Certificate2> SignatureValidationCertificates { get; set; } = new List<X509Certificate2>();
        public X509CertificateValidationMode CertificateValidationMode { get; set; } = X509CertificateValidationMode.ChainTrust;
        public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;
        public X509CertificateValidator CustomCertificateValidator { get; set; }
#if NETFULL
        public SecurityTokenResolver CustomIssuerTokenResolver { get; set; }
        public IdentityModelCaches TokenReplayCache { get; set; }
        public TimeSpan? TokenReplayCacheExpirationPeriod { get; set; }
#else
        public ITokenReplayCache TokenReplayCache { get; set; }
#endif
        public bool SaveBootstrapContext { get; set; } = false;

        /// <summary>
        /// By default no replayed validation is performed. Validation requires that TokenReplayCache has been set.
        /// </summary>
        public bool DetectReplayedTokens { get; set; } = false;

        public bool AudienceRestricted { get; set; } = true;
        public List<string> AllowedAudienceUris { get; set; } = new List<string>();

        /// <summary>
        /// Sign and validate signed authn requests.
        /// </summary>
        public bool SignAuthnRequest { get; set; } = false;

        /// <summary>
        /// Sign type for the authn responses created by the library.
        /// </summary>
        public Saml2AuthnResponseSignTypes AuthnResponseSignType { get; set; } = Saml2AuthnResponseSignTypes.SignResponse;

        /// <summary>
        /// Include key info name in signature.
        /// </summary>
        public bool IncludeKeyInfoName { get; set; }
    }
}
