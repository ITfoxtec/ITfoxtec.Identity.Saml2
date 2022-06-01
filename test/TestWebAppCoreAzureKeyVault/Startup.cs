using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2;
using TestWebAppCoreAzureKeyVault.Identity;
using Azure.Core;
using Azure.Identity;
using ITfoxtec.Identity.Saml2.MvcCore;
using System.Net.Http;

namespace TestWebAppCoreAzureKeyVault
{
    public class Startup
    {
        public static IWebHostEnvironment AppEnvironment { get; private set; }

        public Startup(IWebHostEnvironment env, IConfiguration configuration)
        {
            AppEnvironment = env;

            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            var saml2Configuration = services.BindConfig<Saml2Configuration>(Configuration, "Saml2");
            services.AddSingleton(serviceProvider => 
            {
                var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
                var tokenCredential = serviceProvider.GetService<TokenCredential>();

                return new Saml2ConfigurationLogic(httpClientFactory, saml2Configuration, tokenCredential)
                {
                    Saml2IdPMetadata = Configuration["Saml2:IdPMetadata"],
                    AzureKeyVaultBaseUrl = Configuration["AzureKeyVault:BaseUrl"],
                    AzureKeyVaultCertificateName = Configuration["AzureKeyVault:CertificateName"]
                };
            });
     
            services.AddSaml2();

            //In production possible use: services.AddSingleton<TokenCredential, DefaultAzureCredential>();
            services.AddSingleton<TokenCredential>(serviceProvider =>
            {
                return new ClientSecretCredential(Configuration["AzureKeyVault:TenantId"], Configuration["AzureKeyVault:ClientId"], Configuration["AzureKeyVault:ClientSecret"]);
            });

            services.AddHttpClient();

            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseSaml2();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
