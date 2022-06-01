#if NET || NETCORE
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace ITfoxtec.Identity.Saml2.MvcCore
{
    public static class ServiceCollectionExtensions
    {
        public static TService BindConfig<TService>(this IServiceCollection services, IConfiguration configuration, string key, Func<IServiceProvider, TService, TService> implementationFactory = null) where TService : class, new()
        {
            var settings = new TService();
            configuration.Bind(key, settings);

            if (implementationFactory == null)
            {
                services.AddSingleton(settings);
            }
            else
            {
                services.AddSingleton((serviceProvider) => 
                {
                    return implementationFactory(serviceProvider, settings);
                });
            }

            return settings;
        }
    }
}
#endif
