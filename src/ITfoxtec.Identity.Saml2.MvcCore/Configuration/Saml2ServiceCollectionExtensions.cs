﻿using Microsoft.Extensions.DependencyInjection;
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
        public static IServiceCollection AddSaml2(this IServiceCollection services, string loginPath = "/Auth/Login", bool slidingExpiration = false)
        {
            services.AddAuthentication(Saml2Constants.AuthenticationScheme)
                .AddCookie(Saml2Constants.AuthenticationScheme, o =>
                {
                    o.LoginPath = new PathString(loginPath);
                    o.SlidingExpiration = slidingExpiration;
                });

            return services;
        }   


        /// <summary>
        /// Add SAML 2.0 configuration.
        /// </summary>
        /// <param name="loginPath">Redirection target used by the handler.</param>
        /// <param name="slidingExpiration">If set to true the handler re-issue a new cookie with a new expiration time any time it processes a request which is more than halfway through the expiration window.</param>
        /// <param name="deniedPath">Redirection if the permissions of the user is denied.</param>
        public static IServiceCollection AddSaml2(this IServiceCollection services, string loginPath = "/Auth/Login", bool slidingExpiration = false, string deniedPath = "/Auth/Denied")
        {
            services.AddAuthentication(Saml2Constants.AuthenticationScheme)
                .AddCookie(Saml2Constants.AuthenticationScheme, o =>
                {
                    o.LoginPath = new PathString(loginPath);
                    o.SlidingExpiration = slidingExpiration;
                    o.AccessDeniedPath = new PathString(deniedPath);
                });

            return services;
        }   

    }
}