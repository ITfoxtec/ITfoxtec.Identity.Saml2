using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// Formats of nameidentifiers
    /// </summary>
    public static class NameIdentifierFormats
    {
        /// <summary>
        /// Unspecified name identifier format
        /// </summary>
        public static Uri Unspecified = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        /// <summary>
        /// Email name identifier format
        /// </summary>
        public static Uri Email = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

        /// <summary>
        /// X509SubjectName name identifier format
        /// </summary>
        public static Uri X509SubjectName = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

        /// <summary>
        /// Windows name identifier format
        /// </summary>
        public static Uri Windows = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName");

        /// <summary>
        /// Kerberos name identifier format
        /// </summary>
        public static Uri Kerberos = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos");

        /// <summary>
        /// Entity name identifier format
        /// </summary>
        public static Uri Entity = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");

        /// <summary>
        /// Persistent name identifier format
        /// </summary>
        public static Uri Persistent = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        /// <summary>
        /// Transient name identifier format
        /// </summary>
        public static Uri Transient = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
    }
}
