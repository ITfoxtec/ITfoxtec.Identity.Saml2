using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Util;
using Microsoft.Extensions.Options;
//using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace TestIdPCore.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        [Route("Login")]
        public IActionResult Login()
        {
            var requestBinding = new Saml2RedirectBinding();
            var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLoginRequest(requestBinding));

            var saml2AuthnRequest = new Saml2AuthnRequest(config);
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnRequest);

                // ****  Handle user login e.g. in GUI ****
                // Test user with session index and claims
                var sessionIndex = Guid.NewGuid().ToString();
                var claims = CreateTestUserClaims(saml2AuthnRequest.Subject?.NameID?.ID);

                return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Success, requestBinding.RelayState, relyingParty, sessionIndex, claims);
            }
            catch (Exception exc)
            {
#if DEBUG
                Debug.WriteLine($"Saml 2.0 Authn Request error: {exc.ToString()}\nSaml Auth Request: '{saml2AuthnRequest.XmlDocument?.OuterXml}'\nQuery String: {Request.QueryString}");
#endif
                return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Responder, requestBinding.RelayState, relyingParty);
            }
        }

        [HttpPost("Logout")]
        public IActionResult Logout()
        {
            var requestBinding = new Saml2PostBinding();
            var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLogoutRequest(requestBinding));

            var saml2LogoutRequest = new Saml2LogoutRequest(config);
            saml2LogoutRequest.SignatureValidationCertificates = new X509Certificate2[] { relyingParty.SignatureValidationCertificate };
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2LogoutRequest);

                // **** Delete user session ****

                return LogoutResponse(saml2LogoutRequest.Id, Saml2StatusCodes.Success, requestBinding.RelayState, saml2LogoutRequest.SessionIndex, relyingParty);
            }
            catch (Exception exc)
            {
#if DEBUG
                Debug.WriteLine($"Saml 2.0 Logout Request error: {exc.ToString()}\nSaml Logout Request: '{saml2LogoutRequest.XmlDocument?.OuterXml}'");
#endif
                return LogoutResponse(saml2LogoutRequest.Id, Saml2StatusCodes.Responder, requestBinding.RelayState, saml2LogoutRequest.SessionIndex, relyingParty);
            }
        }

        private string ReadRelyingPartyFromLoginRequest<T>(Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2AuthnRequest(config))?.Issuer;
        }

        private string ReadRelyingPartyFromLogoutRequest<T>(Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2LogoutRequest(config))?.Issuer;
        }

        private IActionResult LoginResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, RelyingParty relyingParty, string sessionIndex = null, IEnumerable<Claim> claims = null)
        {
            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = relayState;

            var saml2AuthnResponse = new Saml2AuthnResponse(config)
            {
                InResponseTo = inResponseTo,
                Status = status,
                Destination = relyingParty.SingleSignOnDestination,
            };
            if (status == Saml2StatusCodes.Success && claims != null)
            {
                saml2AuthnResponse.SessionIndex = sessionIndex;

                var claimsIdentity = new ClaimsIdentity(claims);
                saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
                saml2AuthnResponse.ClaimsIdentity = claimsIdentity;

                var token = saml2AuthnResponse.CreateSecurityToken(relyingParty.Issuer);
            }

            return responsebinding.Bind(saml2AuthnResponse).ToActionResult();
        }

        private IActionResult LogoutResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, string sessionIndex, RelyingParty relyingParty)
        {
            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = relayState;

            var saml2LogoutResponse = new Saml2LogoutResponse(config)
            {
                InResponseTo = inResponseTo,
                Status = status,
                Destination = relyingParty.SingleLogoutResponseDestination,
                SessionIndex = sessionIndex
            };

            return responsebinding.Bind(saml2LogoutResponse).ToActionResult();
        }

        private RelyingParty ValidateRelyingParty(string issuer)
        {
            var validRelyingPartys = new List<RelyingParty>();
            validRelyingPartys.Add(new RelyingParty
            {
                Issuer = "urn:itfoxtec:identity:saml2:testwebapp",
                SingleSignOnDestination = new Uri("https://localhost:44327/Auth/AssertionConsumerService"),
                SingleLogoutResponseDestination = new Uri("https://localhost:44327/Auth/LoggedOut"),
                SignatureValidationCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebapp_Certificate.crt"))
            });
            validRelyingPartys.Add(new RelyingParty
            {
                Issuer = "itfoxtec-testwebappcore",
                SingleSignOnDestination = new Uri("https://localhost:44306/Auth/AssertionConsumerService"),
                SingleLogoutResponseDestination = new Uri("https://localhost:44306/Auth/LoggedOut"),
                SignatureValidationCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebappcore_Certificate.crt"))
            });
            validRelyingPartys.Add(new RelyingParty
            {
                Issuer = "urn:itfoxtec:identity:saml2:testwebappcoreframework",
                SingleSignOnDestination = new Uri("https://localhost:44307/Auth/AssertionConsumerService"),
                SingleLogoutResponseDestination = new Uri("https://localhost:44307/Auth/LoggedOut"),
                SignatureValidationCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebappcore_Certificate.crt"))
            });
            validRelyingPartys.Add(new RelyingParty
            {
                Issuer = "urn:itfoxtec:identity:saml2:testwebappcoreAzureKeyVault",
                SingleSignOnDestination = new Uri("https://localhost:44308/Auth/AssertionConsumerService"),
                SingleLogoutResponseDestination = new Uri("https://localhost:44308/Auth/LoggedOut"),
                SignatureValidationCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebappcore_Certificate.crt"))
            });

            return validRelyingPartys.Where(rp => rp.Issuer.Equals(issuer, StringComparison.InvariantCultureIgnoreCase)).Single();
        }

        class RelyingParty
        {
            public string Issuer { get; set; }

            public Uri SingleSignOnDestination { get; set; }

            public Uri SingleLogoutResponseDestination { get; set; }

            public X509Certificate2 SignatureValidationCertificate { get; set; }
        }

        private IEnumerable<Claim> CreateTestUserClaims(string selectedNameID)
        {
            var userId = selectedNameID ?? "12345";
            yield return new Claim(ClaimTypes.NameIdentifier, userId);
            yield return new Claim(ClaimTypes.Upn, $"{userId}@email.test");
            yield return new Claim(ClaimTypes.Email, $"{userId}@someemail.test");
        }
    }
}        