using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Util;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2;
using System.ServiceModel.Security;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;

namespace TestWebAppCore
{
    public class Startup
    {
        public static IHostingEnvironment AppEnvironment { get; private set; }

        public Startup(IHostingEnvironment env, IConfiguration configuration)
        {
            AppEnvironment = env;

            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var saml2Configuration = new Saml2Configuration
            {
                Issuer = new Uri(Configuration["Saml2:Issuer"]),
                // SingleSignOnDestination = new Uri(Configuration["Saml2:SingleSignOnDestination"]),
                // SingleLogoutDestination = new Uri(Configuration["Saml2:SingleLogoutDestination"]),

                SignatureAlgorithm = Configuration["Saml2:SignatureAlgorithm"],
                SigningCertificate = CertificateUtil.Load(AppEnvironment.MapToPhysicalFilePath(Configuration["Saml2:SigningCertificate"]), Configuration["Saml2:SigningCertificatePassword"]),

                CertificateValidationMode = (X509CertificateValidationMode)Enum.Parse(typeof(X509CertificateValidationMode), Configuration["Saml2:CertificateValidationMode"]),
                RevocationMode = (X509RevocationMode)Enum.Parse(typeof(X509RevocationMode), Configuration["Saml2:RevocationMode"]),
            };
            //saml2Configuration.SignatureValidationCertificates.Add(CertificateUtil.Load(AppEnvironment.MapToPhysicalFilePath(Configuration["Saml2:SignatureValidationCertificate"])));
            saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);


            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(Configuration["Saml2:IdPMetadata"]));            
            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
            }
            else
            {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }

            services.AddSaml2(saml2Configuration);

            // Add framework services.
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseSaml2();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
