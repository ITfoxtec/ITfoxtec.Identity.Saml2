#if NETFULL
#else
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Configuration
{
    public class Saml2CertificateValidator
    {
        public Saml2IdentityConfiguration IdentityConfiguration { get; set; }

        public void Validate(X509Certificate2 certificate) 
        {
                //TODO use IdentityConfiguration CertificateValidationMode and RevocationMode
                X509Chain chain = new X509Chain();
                chain.ChainPolicy = new X509ChainPolicy();
                var validCert = chain.Build(certificate);
        }
    }
}
#endif
