﻿using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TestWebAppCore.Identity;
using System.Security.Authentication;

namespace TestWebAppCore.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public AuthController(Saml2Configuration config)
        {
            this.config = config;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)
            {
                //AssertionConsumerServiceIndex = 0,
                //AttributeConsumingServiceIndex = 0,
                //AssertionConsumerServiceUrl = new Uri("https://test.com"),

                //ForceAuthn = true,
                Subject = new Subject { NameID = new NameID { ID = "abcd" } },
                NameIdPolicy = new NameIdPolicy { AllowCreate = true, Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" },
                //Extensions = new AppExtensions(),
                RequestedAuthnContext = new RequestedAuthnContext
                {
                    Comparison = AuthnContextComparisonTypes.Minimum,
                    AuthnContextClassRef = [AuthnContextClassTypes.PasswordProtectedTransport.OriginalString],
                },
                Scoping = new Scoping 
                { 
                    IDPList = new IDPList
                    { 
                        IDPEntry = [new IDPEntry 
                        {
                            ProviderID = "https://qaz.org",
                            Name = "xxx",
                            Loc = "https://wsx.org"
                        }], 
                        GetComplete = "xxx" 
                    }, 
                    RequesterID = ["https://xyz.org"] 
                }
            }).ToActionResult();
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            httpRequest.Binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            return binding.Bind(saml2LogoutRequest).ToActionResult();
        }

        [Route("LoggedOut")]
        public IActionResult LoggedOut()
        {
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            httpRequest.Binding.Unbind(httpRequest, new Saml2LogoutResponse(config));

            return Redirect(Url.Content("~/"));
        }

        [Route("SingleLogout")]
        public async Task<IActionResult> SingleLogout()
        {
            Saml2StatusCodes status;
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            var logoutRequest = new Saml2LogoutRequest(config, User);
            try
            {
                httpRequest.Binding.Unbind(httpRequest, logoutRequest);
                status = Saml2StatusCodes.Success;
                await logoutRequest.DeleteSession(HttpContext);
            }
            catch (Exception exc)
            {
                // log exception
                Debug.WriteLine("SingleLogout error: " + exc.ToString());
                status = Saml2StatusCodes.RequestDenied;
            }

            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = httpRequest.Binding.RelayState;
            var saml2LogoutResponse = new Saml2LogoutResponse(config)
            {
                InResponseToAsString = logoutRequest.IdAsString,
                Status = status,
            };
            return responsebinding.Bind(saml2LogoutResponse).ToActionResult();
        }
    }
}
