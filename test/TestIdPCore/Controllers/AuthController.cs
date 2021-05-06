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
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens.Saml2;
using TestIdPCore.Models;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;

namespace TestIdPCore.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Settings settings;
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Settings> settingsAccessor, IOptions<Saml2Configuration> configAccessor)
        {
            settings = settingsAccessor.Value;
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
                //saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single());
                saml2AuthnResponse.ClaimsIdentity = claimsIdentity;

                var token = saml2AuthnResponse.CreateSecurityToken(relyingParty.Issuer, subjectConfirmationLifetime: 5, issuedTokenLifetime: 60);
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
            foreach (var rp in settings.RelyingParties)
            {
                try
                {
                    if (string.IsNullOrEmpty(rp.Issuer))
                    {
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(rp.Metadata));
                        if (entityDescriptor.SPSsoDescriptor != null)
                        {
                            rp.Issuer = entityDescriptor.EntityId;
                            rp.SingleSignOnDestination = entityDescriptor.SPSsoDescriptor.AssertionConsumerServices.Where(a => a.IsDefault).OrderBy(a => a.Index).First().Location;
                            var singleLogoutService = entityDescriptor.SPSsoDescriptor.SingleLogoutServices.First();
                            rp.SingleLogoutResponseDestination = singleLogoutService.ResponseLocation ?? singleLogoutService.Location;
                            rp.SignatureValidationCertificate = entityDescriptor.SPSsoDescriptor.SigningCertificates.First();
                        }
                        else
                        {
                            throw new Exception($"SPSsoDescriptor not loaded from metadata '{rp.Metadata}'.");
                        }
                    }
                }
                catch (Exception exc)
                {
                    //log error
#if DEBUG
                    Debug.WriteLine($"SPSsoDescriptor error: {exc.ToString()}");
#endif
                }
            }

            return settings.RelyingParties.Where(rp => rp.Issuer != null && rp.Issuer.Equals(issuer, StringComparison.InvariantCultureIgnoreCase)).Single();
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