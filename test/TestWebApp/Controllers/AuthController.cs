using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Mvc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web.Mvc;
using System.Security.Claims;
using TestWebApp.Identity;
using System.IdentityModel.Services;
using System.Security.Authentication;

namespace TestWebApp.Controllers
{
    [AllowAnonymous]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public AuthController()
        {
            config = IdentityConfig.Saml2Configuration;
        }

        public ActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)
            {
                //ForceAuthn = true,
                //NameIdPolicy = new NameIdPolicy { AllowCreate = true, Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" },
                //RequestedAuthnContext = new RequestedAuthnContext
                //{
                //    Comparison = AuthnContextComparisonTypes.Exact,
                //    AuthnContextClassRef = new string[] { AuthnContextClassTypes.PasswordProtectedTransport.OriginalString },
                //},
            }).ToActionResult();
        }

        public ActionResult AssertionConsumerService()
        {
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            httpRequest.Binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);
            saml2AuthnResponse.CreateSession(claimsAuthenticationManager: new DefaultClaimsAuthenticationManager());

            var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var logoutRequest = new Saml2LogoutRequest(config, ClaimsPrincipal.Current).DeleteSession();
            return binding.Bind(logoutRequest).ToActionResult();
        }

        public ActionResult LoggedOut()
        {
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            httpRequest.Binding.Unbind(httpRequest, new Saml2LogoutResponse(config));

            FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            FederatedAuthentication.SessionAuthenticationModule.SignOut();

            return Redirect(Url.Content("~/"));
        }

        public ActionResult SingleLogout()
        {
            Saml2StatusCodes status;
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            var logoutRequest = new Saml2LogoutRequest(config, ClaimsPrincipal.Current);
            try
            {
                httpRequest.Binding.Unbind(httpRequest, logoutRequest);
                status = Saml2StatusCodes.Success;
                logoutRequest.DeleteSession();
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
