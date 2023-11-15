using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2.MvcCore.Configuration
{
    public static class Saml2ServiceCollectionExtensions
    {
        /// <summary>
        /// Add SAML 2.0 configuration.
        /// </summary>
        /// <param name="loginPath">Redirection target used by the handler.</param>
        /// <param name="slidingExpiration">If set to true the handler re-issue a new cookie with a new expiration time any time it processes a request which is more than halfway through the expiration window.</param>
        /// <param name="accessDeniedPath">If configured, access denied redirection target used by the handler.</param>
        /// <param name="sessionStore">Allow configuration of a custom ITicketStore.</param>
        /// <param name="cookieSameSite">The SameSite attribute of the cookie. The default value is Microsoft.AspNetCore.Http.SameSiteMode.Lax</param>
        /// <param name="cookieDomain">If configured, the domain to associate the cookie with.</param>
        /// <param name="cookieSecurePolicy">The cookie policy. The default value is Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest.</param>
        public static IServiceCollection AddSaml2(this IServiceCollection services, string loginPath = "/Auth/Login", bool slidingExpiration = false, string accessDeniedPath = null, ITicketStore sessionStore = null, SameSiteMode cookieSameSite = SameSiteMode.Lax, string cookieDomain = null, CookieSecurePolicy cookieSecurePolicy = CookieSecurePolicy.SameAsRequest)
        {
            services.AddAuthentication(Saml2Constants.AuthenticationScheme)
                .AddCookie(Saml2Constants.AuthenticationScheme, o =>
                {
                    o.LoginPath = new PathString(loginPath);
                    o.SlidingExpiration = slidingExpiration;
                    if (!string.IsNullOrEmpty(accessDeniedPath))
                    {
                        o.AccessDeniedPath = new PathString(accessDeniedPath);
                    }
                    if (sessionStore != null)
                    {
                        o.SessionStore = sessionStore;
                    }
                    o.Cookie.SameSite = cookieSameSite;
                    o.Cookie.SecurePolicy = cookieSecurePolicy;
                    if (!string.IsNullOrEmpty(cookieDomain))
                    {
                        o.Cookie.Domain = cookieDomain;
                    }
                });

            return services;
        }   
    }
}
