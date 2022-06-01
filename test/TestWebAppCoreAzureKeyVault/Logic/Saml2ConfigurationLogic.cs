using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using RSAKeyVaultProvider;
using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace TestWebAppCoreAzureKeyVault.Identity
{
    public class Saml2ConfigurationLogic
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly Saml2Configuration config;
        private readonly TokenCredential tokenCredential;

        public Saml2ConfigurationLogic(IHttpClientFactory httpClientFactory, Saml2Configuration config, TokenCredential tokenCredential)
        {
            this.httpClientFactory = httpClientFactory;
            this.config = config;
            this.tokenCredential = tokenCredential;
        }

        public string Saml2IdPMetadata{ get; set; }
        public string AzureKeyVaultBaseUrl { get; set; }
        public string AzureKeyVaultCertificateName { get; set; }

        public Saml2Configuration GetSaml2Configuration()
        {
            var saml2Configuration = new Saml2Configuration
            {
                Issuer = config.Issuer,
                SignatureAlgorithm = config.SignatureAlgorithm,
                CertificateValidationMode = config.CertificateValidationMode,
                RevocationMode = config.RevocationMode
            };

            var certificateClient = new CertificateClient(new Uri(AzureKeyVaultBaseUrl), tokenCredential);
            var certificateWithPolicy = certificateClient.GetCertificate(AzureKeyVaultCertificateName);

            var publicCertificate = new X509Certificate2(certificateWithPolicy.Value.Cer);
            var rsa = RSAFactory.Create(tokenCredential, certificateWithPolicy.Value.KeyId, new Azure.Security.KeyVault.Keys.JsonWebKey(publicCertificate.GetRSAPublicKey()));
            saml2Configuration.SigningCertificate = new Saml2X509Certificate(publicCertificate, rsa);

            //saml2Configuration.SignAuthnRequest = true;

            saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

            var entityDescriptor = new EntityDescriptor(httpClientFactory);
            entityDescriptor.ReadIdPSsoDescriptorFromUrlAsync(new Uri(Saml2IdPMetadata)).GetAwaiter().GetResult();
            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
                saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
            }
            else
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }

            return saml2Configuration;
        }

    }
}
