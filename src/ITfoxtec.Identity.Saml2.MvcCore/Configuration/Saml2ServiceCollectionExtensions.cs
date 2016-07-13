using ITfoxtec.Identity.Saml2.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2.MvcCore.Configuration
{
    public static class Saml2ServiceCollectionExtensions
    {
        /// <summary>
        /// Add SAML 2.0 configuration.
        /// </summary>
        public static IServiceCollection AddSaml2(this IServiceCollection services, Saml2Configuration configuration)
        {           
            services.AddSingleton(configuration);

            return services;
        }
    }
}
