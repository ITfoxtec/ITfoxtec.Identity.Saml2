using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using System;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2.MvcCore
{
    public static class Saml2ResponseExtensions
    {
        /// <summary>
        /// Create a Claims Principal and a Federated Authentication Session for the authenticated user.
        /// </summary>
        /// <param name="lifetime">The period from the current time during which the token is valid. The ValidFrom property will be set to UtcNow and the ValidTo property will be set to ValidFrom plus the period specified by this parameter. Default lifetime is 10 Hours.</param>
        /// <param name="isPersistent">If the IsPersistent property is true, the cookie is written as a persistent cookie. Persistent cookies remain valid after the browser is closed until they expire.</param>
        public static async Task<ClaimsPrincipal> CreateSession(this Saml2AuthnResponse saml2AuthnResponse, HttpContext httpContext, TimeSpan? lifetime = null, bool isPersistent = false, Func<ClaimsPrincipal, ClaimsPrincipal> claimsTransform = null)
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

            if (claimsTransform != null)
            {
                principal = claimsTransform(principal);
            }

            await httpContext.Authentication.SignInAsync(Saml2Constants.AuthenticationScheme, principal, 
                new AuthenticationProperties
                {
                    AllowRefresh = false,
                    IsPersistent = isPersistent,
                    IssuedUtc = new DateTimeOffset(saml2AuthnResponse.SecurityTokenValidFrom),
                    ExpiresUtc = lifetime.HasValue ? new DateTimeOffset(DateTime.UtcNow + lifetime.Value) : new DateTimeOffset(saml2AuthnResponse.SecurityTokenValidTo),
                });

            return principal;
        }
    }
}
