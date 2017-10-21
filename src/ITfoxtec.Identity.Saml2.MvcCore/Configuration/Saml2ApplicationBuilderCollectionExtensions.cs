using Microsoft.AspNetCore.Builder;

namespace ITfoxtec.Identity.Saml2.MvcCore.Configuration
{
    public static class Saml2ApplicationBuilderCollectionExtensions
    {
        /// <summary>
        /// Use SAML 2.0.
        /// </summary>
        public static IApplicationBuilder UseSaml2(this IApplicationBuilder app)
        {
            app.UseAuthentication();                       

            return app;
        }

    }
}
