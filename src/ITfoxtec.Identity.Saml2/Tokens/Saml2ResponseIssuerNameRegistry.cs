#if NETFULL
using System;
using System.IdentityModel.Tokens;

namespace ITfoxtec.Identity.Saml2.Tokens
{
    class Saml2ResponseIssuerNameRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken, string requestedIssuerName)
        {
            return requestedIssuerName;
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            throw new InvalidOperationException();
        }
    }
}
#endif
