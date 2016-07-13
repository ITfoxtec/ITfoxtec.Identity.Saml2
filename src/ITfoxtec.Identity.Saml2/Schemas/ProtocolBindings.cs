using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// Protocol bindings
    /// </summary>
    public static class ProtocolBindings
    {
        /// <summary>
        /// HTTP Redirect protocol binding
        /// </summary>
        public static Uri HttpRedirect= new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        /// <summary>
        /// HTTP Post protocol binding
        /// </summary>
        public static Uri HttpPost= new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    }
}
