using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading;

namespace ITfoxtec.Identity.Saml2.Mvc
{
    public static class Saml2RequestExtensions
    {
        /// <summary>
        /// Delete the current Federated Authentication Session.
        /// </summary>
        public static Saml2LogoutRequest DeleteSession(this Saml2LogoutRequest saml2LogoutRequest)
        {
            FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
            return saml2LogoutRequest;
        }
    }
}
