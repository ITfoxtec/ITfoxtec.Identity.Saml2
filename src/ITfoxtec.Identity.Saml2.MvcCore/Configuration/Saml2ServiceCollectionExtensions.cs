using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2.MvcCore.Configuration
{
    public static class Saml2ServiceCollectionExtensions
    {
        /// <summary>
        /// Add SAML 2.0 configuration.
        /// </summary>
        public static IServiceCollection AddSaml2(this IServiceCollection services)
        {
            services.AddAuthentication(Saml2Constants.AuthenticationScheme)
                .AddCookie(Saml2Constants.AuthenticationScheme, o =>
                {
                    o.LoginPath = new PathString("/Auth/Login");
                });

            return services;
        }   
    }
}
