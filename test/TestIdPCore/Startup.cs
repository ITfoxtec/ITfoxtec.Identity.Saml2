using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Util;
using TestIdPCore.Models;
using System;
using Microsoft.IdentityModel.Logging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TestIdPCore
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
            IdentityModelEventSource.ShowPII = true;

            services.BindConfig<Settings>(Configuration, "Settings");
            services.BindConfig<Saml2Configuration>(Configuration, "Saml2", (serviceProvider, saml2Configuration) =>
            {
                if (Configuration.GetValue<bool>("Saml2:UseEcdsaSigningCertificate"))
                {
                    saml2Configuration.SignatureAlgorithm = Saml2SecurityAlgorithms.EcdsaSha256Signature;
                    saml2Configuration.SigningCertificate = CreateEcdsaSigningCertificate(saml2Configuration);
                }
                else
                {
                    saml2Configuration.SigningCertificate = CertificateUtil.Load(AppEnvironment.MapToPhysicalFilePath(Configuration["Saml2:SigningCertificateFile"]), Configuration["Saml2:SigningCertificatePassword"]);
                }
                if (!saml2Configuration.SigningCertificate.IsValidLocalTime())
                {
                    throw new Exception("The IdP signing certificates has expired.");
                }
                saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

                saml2Configuration.IncludeKeyInfoName = true;

                return saml2Configuration;
            });

            services.AddSaml2();
            services.AddHttpClient();

            services.AddControllersWithViews();
        }

        private static X509Certificate2 CreateEcdsaSigningCertificate(Saml2Configuration saml2Configuration)
        {
            using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var request = new CertificateRequest($"CN={saml2Configuration.Issuer}", ecdsa, HashAlgorithmName.SHA256);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
                return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));
            }
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
