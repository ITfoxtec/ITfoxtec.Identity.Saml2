using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    /// <summary>
    /// X509Certificate2 supporting dynimic privare RSA key. 
    /// Supporting Azure Key Vault.
    /// </summary>
    public class Saml2X509Certificate : X509Certificate2
    {
        /// <summary>
        /// Private RSA key.
        /// </summary>
        public RSA RSA { get; protected set; }
    
        public Saml2X509Certificate(X509Certificate2 certificate, RSA rsa): base(certificate)
        {
            RSA = rsa;
        }

        /// <summary>
        /// Get the private RSA key.
        /// </summary>
        public RSA GetRSAPrivateKey()
        {
            return RSA;
        }
    }
}
