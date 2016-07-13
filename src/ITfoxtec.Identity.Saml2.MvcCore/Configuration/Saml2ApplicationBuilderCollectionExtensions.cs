using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace ITfoxtec.Identity.Saml2.MvcCore.Configuration
{
    public static class Saml2ApplicationBuilderCollectionExtensions
    {
        /// <summary>
        /// Use SAML 2.0.
        /// </summary>
        public static IApplicationBuilder UseSaml2(this IApplicationBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationScheme = Saml2Constants.AuthenticationScheme,
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                LoginPath = new PathString("/Auth/Login"),
            });

            return app;
        }

    }
}
