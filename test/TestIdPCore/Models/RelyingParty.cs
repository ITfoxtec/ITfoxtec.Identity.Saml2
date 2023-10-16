using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace TestIdPCore.Models
{
    public class RelyingParty
    {
        public string Metadata { get; set; }

        public string Issuer { get; set; }

        public Uri AcsDestination { get; set; }

        public bool UseAcsArtifact { get; set; } = false;

        public Uri SingleLogoutDestination { get; set; }

        public IEnumerable<X509Certificate2> SignatureValidationCertificates { get; set; }

        public IEnumerable<X509Certificate2> EecryptionCertificates { get; set; }
    }
}
