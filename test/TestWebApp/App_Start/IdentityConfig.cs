using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using ITfoxtec.Identity.Saml2.Util;
using System;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Web;
using System.Web.Helpers;

namespace TestWebApp
{
    public static class IdentityConfig
    {
        public static Saml2Configuration Saml2Configuration { get; private set; } = new Saml2Configuration();

        public static void RegisterIdentity()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;

            Saml2Configuration.Issuer = ConfigurationManager.AppSettings["Saml2:Issuer"];
            //Saml2Configuration.SingleSignOnDestination = new Uri(ConfigurationManager.AppSettings["Saml2:SingleSignOnDestination"]);
            //Saml2Configuration.SingleLogoutDestination = new Uri(ConfigurationManager.AppSettings["Saml2:SingleLogoutDestination"]);

            Saml2Configuration.SignatureAlgorithm = ConfigurationManager.AppSettings["Saml2:SignatureAlgorithm"];
            //Saml2Configuration.SignAuthnRequest = true;
            Saml2Configuration.SigningCertificate = CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml2:SigningCertificateFile"]), ConfigurationManager.AppSettings["Saml2:SigningCertificatePassword"]);
            //Saml2Configuration.DecryptionCertificates.Add(Saml2Configuration.SigningCertificate);

            //Saml2Configuration.SignatureValidationCertificates.Add(CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml2:SignatureValidationCertificate"])));

            Saml2Configuration.CertificateValidationMode = (X509CertificateValidationMode)Enum.Parse(typeof(X509CertificateValidationMode), ConfigurationManager.AppSettings["Saml2:CertificateValidationMode"]);
            Saml2Configuration.RevocationMode = (X509RevocationMode)Enum.Parse(typeof(X509RevocationMode), ConfigurationManager.AppSettings["Saml2:RevocationMode"]);

            Saml2Configuration.AllowedAudienceUris.Add(Saml2Configuration.Issuer);

            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(ConfigurationManager.AppSettings["Saml2:IdPMetadata"]));
            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                Saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
                Saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                Saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                foreach (var signingCertificate in entityDescriptor.IdPSsoDescriptor.SigningCertificates)
                {
                    if (signingCertificate.IsValidLocalTime())
                    {
                        Saml2Configuration.SignatureValidationCertificates.Add(signingCertificate);
                    }
                }
                if (Saml2Configuration.SignatureValidationCertificates.Count <= 0)
                {
                    throw new Exception("The IdP signing certificates has expired.");
                }
                if(entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
                {
                    Saml2Configuration.SignAuthnRequest = entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
                }
            }
            else
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }
        }
    }
}