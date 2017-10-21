using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace ITfoxtec.Identity.Saml2.MvcCore
{
    public static class Saml2RequestExtensions
    {
        /// <summary>
        /// Delete the current Session.
        /// </summary>
        public static async Task<Saml2LogoutRequest> DeleteSession(this Saml2LogoutRequest saml2LogoutRequest, HttpContext httpContext)
        {
            await httpContext.SignOutAsync(Saml2Constants.AuthenticationScheme);
            return saml2LogoutRequest;
        }
    }
}
