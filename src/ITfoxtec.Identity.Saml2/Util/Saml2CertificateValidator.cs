#if !NETFULL
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Selectors;
using System.ServiceModel.Security;
using Microsoft.IdentityModel.Tokens;

namespace ITfoxtec.Identity.Saml2.Util
{
    public class Saml2CertificateValidator : X509CertificateValidator
    {
        public StoreLocation TrustedStoreLocation { get; set; } = StoreLocation.LocalMachine;
        public X509CertificateValidationMode CertificateValidationMode { get; set; } = X509CertificateValidationMode.ChainTrust;
        public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

        public override void Validate(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            switch (CertificateValidationMode)
            {
                case X509CertificateValidationMode.None:
                    break;

                case X509CertificateValidationMode.PeerTrust:
                    ValidatePeerTrust(certificate);
                    break;

                case X509CertificateValidationMode.ChainTrust:
                    ValidateChainTrust(certificate);
                    break;

                case X509CertificateValidationMode.PeerOrChainTrust:
                    ValidatePeerTrust(certificate);
                    ValidateChainTrust(certificate);
                    break;

                case X509CertificateValidationMode.Custom:
                default:
                    throw new NotSupportedException("X509 certificate validation mode not supported.");
            }
        }

        private void ValidatePeerTrust(X509Certificate2 certificate)
        {
            var store = new X509Store(StoreName.TrustedPeople, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                if (store.Certificates.Find(X509FindType.FindByThumbprint, certificate.GetCertHashString(), false)?.Count > 0)
                {
                    return;
                }
            }
            finally
            {
                store.Close();
            }

            new SecurityTokenValidationException($"Invalid X509 certificate peer trust.{GetCertificateInformation(certificate)}'.");
        }

        private void ValidateChainTrust(X509Certificate2 certificate)
        {
            bool useMachineContext = TrustedStoreLocation == StoreLocation.LocalMachine;
            var chain = new X509Chain(useMachineContext);
            chain.ChainPolicy = new X509ChainPolicy
            {
                VerificationTime = DateTimeOffset.UtcNow.UtcDateTime,
                RevocationMode = RevocationMode
            };
            if (chain.Build(certificate))
            {
                new SecurityTokenValidationException($"Invalid X509 certificate chain.{GetCertificateInformation(certificate)}{GetChainStatusInformation(chain.ChainStatus)}.");
            }
        }

        private string GetCertificateInformation(X509Certificate2 certificate)
        {
            return $" Certificate name:'{certificate.SubjectName?.Name}' and thumbprint:'{certificate.Thumbprint}'.";
        }

        private string GetChainStatusInformation(X509ChainStatus[] chainStatus)
        {
            if (chainStatus != null)
            {
                var errors = new List<string>();
                foreach (var item in chainStatus)
                {
                    errors.Add(item.StatusInformation);
                }
                return $" Chain Status:'{string.Join(' ', errors)}'.";
            }
            return string.Empty;
        }
    }
}
#endif
