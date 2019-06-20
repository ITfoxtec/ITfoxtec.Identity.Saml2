using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ITfoxtec.Identity.Helpers;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2;
using Microsoft.AspNetCore.Mvc;
using TestWebAppCoreAzureKeyVault.AzureKeyVault;
using Microsoft.Azure.KeyVault;
using TestWebAppCoreAzureKeyVault.Identity;

namespace TestWebAppCoreAzureKeyVault
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

        public void ConfigureServices(IServiceCollection services)
        {
            var saml2Configuration = new Saml2Configuration();
            Configuration.Bind("Saml2", saml2Configuration);

            services.AddSingleton(serviceProvider => 
            {
                var keyVaultClient = serviceProvider.GetService<KeyVaultClient>();

                return new Saml2ConfigurationLogic(saml2Configuration, keyVaultClient)
                {
                    Saml2IdPMetadata = Configuration["Saml2:IdPMetadata"],
                    AzureKeyVaultBaseUrl = Configuration["AzureKeyVault:BaseUrl"],
                    AzureKeyVaultCertificateName = Configuration["AzureKeyVault:CertificateName"]
                };
            });
     
            services.AddSaml2();

            services.AddTransient<TokenHelper>();
            services.AddSingleton(serviceProvider =>
            {
                var tokenHelper = serviceProvider.GetService<TokenHelper>();
                return AppKeyVaultClient.GetClient(Configuration["AzureKeyVault:ClientId"], Configuration["AzureKeyVault:ClientSecret"], tokenHelper);
            });

            services.AddHttpClient();

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
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
