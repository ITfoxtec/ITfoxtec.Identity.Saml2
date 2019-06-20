using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Azure.KeyVault;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace TestWebAppCoreAzureKeyVault.Identity
{
    public class Saml2ConfigurationLogic
    {
        private readonly Saml2Configuration config;
        private readonly KeyVaultClient keyVaultClient;

        public Saml2ConfigurationLogic(Saml2Configuration config, KeyVaultClient keyVaultClient)
        {
            this.config = config;
            this.keyVaultClient = keyVaultClient;
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

            var certificateBundle = keyVaultClient.GetCertificateAsync(AzureKeyVaultBaseUrl, AzureKeyVaultCertificateName).GetAwaiter().GetResult();
            var publicCertificate = new X509Certificate2(certificateBundle.Cer);

            var rsa = keyVaultClient.ToRSA(certificateBundle.KeyIdentifier, publicCertificate);
            saml2Configuration.SigningCertificate = new Saml2X509Certificate(publicCertificate, rsa);

            //saml2Configuration.SignAuthnRequest = true;

            saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(Saml2IdPMetadata));
            if (entityDescriptor.IdPSsoDescriptor != null)
            {
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
