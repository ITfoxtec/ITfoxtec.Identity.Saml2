using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    public static class SamlTokenTypes
    {
        public static Uri Saml11TokenProfile11 = new Uri("urn:oasis:names:tc:SAML:1.0:assertion");
        public static Uri Saml2TokenProfile11 = new Uri("urn:oasis:names:tc:SAML:2.0:assertion");
        public const string OasisWssSaml11TokenProfile11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        public const string OasisWssSaml2TokenProfile11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    }
}
