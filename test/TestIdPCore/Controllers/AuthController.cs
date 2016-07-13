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
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Util;

namespace TestIdPCore.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public object SecurityAlgorithms { get; private set; }

        public AuthController(Saml2Configuration config)
        {
            this.config = config;
        }

        [Route("Login")]
        public IActionResult Login()
        {
            var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLoginRequest());

            var requestBinding = new Saml2RedirectBinding();
            var saml2AuthnRequest = new Saml2AuthnRequest(config);
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnRequest);

                // ****  Handle user login e.g. in GUI ****
                // Test user with session index and claims
                var sessionIndex = Guid.NewGuid().ToString();
                var claims = CreateTestUserClaims();

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
            var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLogoutRequest());

            var requestBinding = new Saml2PostBinding();
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

        private Uri ReadRelyingPartyFromLoginRequest()
        {
            return new Saml2RedirectBinding().ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2AuthnRequest(config))?.Issuer;
        }

        private Uri ReadRelyingPartyFromLogoutRequest()
        {
            return new Saml2PostBinding().ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2LogoutRequest(config))?.Issuer;
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

        private RelyingParty ValidateRelyingParty(Uri issuer)
        {
            var validRelyingPartys = new List<RelyingParty>();
            validRelyingPartys.Add(new RelyingParty
            {
                Issuer = new Uri("urn:itfoxtec:identity:saml2:testwebapp"),
                SingleSignOnDestination = new Uri("http://localhost:3112/Auth/AssertionConsumerService"),
                SingleLogoutResponseDestination = new Uri("http://localhost:3112/Auth/LoggedOut"),
                SignatureValidationCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebapp_Certificate.crt"))
            });
            validRelyingPartys.Add(new RelyingParty
            {
                Issuer = new Uri("urn:itfoxtec:identity:saml2:testwebappcore"),
                SingleSignOnDestination = new Uri("https://localhost:44306/Auth/AssertionConsumerService"),
                SingleLogoutResponseDestination = new Uri("https://localhost:44306/Auth/LoggedOut"),
                SignatureValidationCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebappcore_Certificate.crt"))
            });

            return validRelyingPartys.Where(rp => rp.Issuer.OriginalString.Equals(issuer.OriginalString, StringComparison.InvariantCultureIgnoreCase)).Single();
        }

        class RelyingParty
        {
            public Uri Issuer { get; set; }

            public Uri SingleSignOnDestination { get; set; }

            public Uri SingleLogoutResponseDestination { get; set; }

            public X509Certificate2 SignatureValidationCertificate { get; set; }
        }

        private IEnumerable<Claim> CreateTestUserClaims()
        {
            yield return new Claim(ClaimTypes.NameIdentifier, "12345");
            yield return new Claim(ClaimTypes.Upn, "12345@email.test");
            yield return new Claim(ClaimTypes.Email, "some@email.test");
        }
    }
}        