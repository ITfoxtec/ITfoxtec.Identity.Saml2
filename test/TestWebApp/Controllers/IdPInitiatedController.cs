using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Mvc;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Util;
using System.Web.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;

namespace TestWebApp.Controllers
{
    [AllowAnonymous]
    public class IdPInitiatedController : Controller
    {
        public ActionResult Initiate()
        {
            var serviceProviderRealm = "https://some-domain.com/some-service-provider";

            var binding = new Saml2PostBinding();
            binding.RelayState = $"RPID={Uri.EscapeDataString(serviceProviderRealm)}";

            var config = new Saml2Configuration();

            config.Issuer = "http://some-domain.com/this-application";
            config.SingleSignOnDestination = new Uri("https://test-adfs.itfoxtec.com/adfs/ls/");
            config.SigningCertificate = CertificateUtil.Load(HttpContext.Server.MapPath("~/App_Data/itfoxtec.identity.saml2.testwebapp_Certificate.pfx"), "!QAZ2wsx");
            config.SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature;

            var appliesToAddress = "https://test-adfs.itfoxtec.com/adfs/services/trust";

            var response = new Saml2AuthnResponse(config);
            response.Status = Saml2StatusCodes.Success;    
   
            var claimsIdentity = new ClaimsIdentity(CreateClaims());
            response.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
            response.ClaimsIdentity = claimsIdentity;
            var token = response.CreateSecurityToken(appliesToAddress);

            return binding.Bind(response).ToActionResult();
        }

        private IEnumerable<Claim> CreateClaims()
        {
            yield return new Claim(ClaimTypes.NameIdentifier, "some-user-identity");
            yield return new Claim(ClaimTypes.Email, "some-user@domain.com");
        }
    }
}
