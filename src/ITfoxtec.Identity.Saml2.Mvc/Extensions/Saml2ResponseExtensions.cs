using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading;

namespace ITfoxtec.Identity.Saml2.Mvc
{
    public static class Saml2ResponseExtensions
    {
        /// <summary>
        /// Create a Claims Principal and a Federated Authentication Session for the authenticated user.
        /// </summary>
        /// <param name="lifetime">The period from the current time during which the token is valid. The ValidFrom property will be set to UtcNow and the ValidTo property will be set to ValidFrom plus the period specified by this parameter. Default lifetime is 10 Hours.</param>
        /// <param name="isReferenceMode">In reference mode, a simple artifact is produced during serialization and the token material is stored in the token cache that is associated with the token handler. The token cache is an instance of a class that derives from SessionSecurityTokenCache. For Web Farm scenarios, the token cache must operate across all nodes in the farm.</param>
        /// <param name="isPersistent">If the IsPersistent property is true, the cookie is written as a persistent cookie. Persistent cookies remain valid after the browser is closed until they expire.</param>
        /// <param name="claimsAuthenticationManager">Possible to add a custom ClaimsAuthenticationManager for handling claims transformation.</param>
        public static ClaimsPrincipal CreateSession(this Saml2AuthnResponse saml2AuthnResponse, TimeSpan? lifetime = null, bool isReferenceMode = false, bool isPersistent = false, ClaimsAuthenticationManager claimsAuthenticationManager = null)
        {
            if (Thread.CurrentPrincipal.Identity.IsAuthenticated)
            {
                throw new InvalidOperationException("There already exist an Authenticated user.");
            }

            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new InvalidOperationException($"The SAML2 Response Status is not Success, the Response Status is: {saml2AuthnResponse.Status}.");
            }

            var principal = new ClaimsPrincipal(saml2AuthnResponse.ClaimsIdentity);

            if (principal.Identity == null || !principal.Identity.IsAuthenticated)
            {
                throw new InvalidOperationException("No Claims Identity created from SAML2 Response.");
            }

            var transformedPrincipal = claimsAuthenticationManager != null ? claimsAuthenticationManager.Authenticate(null, principal) : principal;
            var sessionSecurityToken = lifetime.HasValue ?
                new SessionSecurityToken(transformedPrincipal, lifetime.Value) :
                new SessionSecurityToken(transformedPrincipal, null, saml2AuthnResponse.Saml2SecurityToken.ValidFrom, saml2AuthnResponse.Saml2SecurityToken.ValidTo);
            sessionSecurityToken.IsReferenceMode = isReferenceMode;
            sessionSecurityToken.IsPersistent = isPersistent;
            FederatedAuthentication.SessionAuthenticationModule.AuthenticateSessionSecurityToken(sessionSecurityToken, true);
            return transformedPrincipal;
        }

        /// <summary>
        /// Delete the current Federated Authentication Session.
        /// </summary>
        public static bool DeleteSession(this Saml2Response saml2Response)
        {
            if (saml2Response.Status == Saml2StatusCodes.Success)
            {
                FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
                FederatedAuthentication.SessionAuthenticationModule.SignOut();
                return true;
            }
            return false;
        }
    }
}
