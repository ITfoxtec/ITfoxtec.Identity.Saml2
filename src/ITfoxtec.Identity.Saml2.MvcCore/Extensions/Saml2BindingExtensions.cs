using Microsoft.AspNetCore.Mvc;

namespace ITfoxtec.Identity.Saml2.MvcCore
{
    /// <summary>
    /// Extension methods for Bindings
    /// </summary>
    public static class Saml2BindingExtensions
    {
        /// <summary>
        /// To Redirect Action Result
        /// </summary>
        public static IActionResult ToActionResult(this Saml2RedirectBinding binding)
        {
            return new RedirectResult(binding.RedirectLocation.OriginalString);
        }

        /// <summary>
        /// To Post Action Result
        /// </summary>
        public static IActionResult ToActionResult(this Saml2PostBinding binding)
        {
            return new ContentResult
            {
                ContentType = "text/html",
                Content = binding.PostContent
            };
        }

        /// <summary>
        /// To Artifact Action Result
        /// </summary>
        public static IActionResult ToActionResult(this Saml2ArtifactBinding binding)
        {
            return new RedirectResult(binding.RedirectLocation.OriginalString);
        }

        /// <summary>
        /// To SOAP Action Result
        /// </summary>
        public static IActionResult ToActionResult(this Saml2SoapEnvelope binding)
        {
            return new ContentResult
            {
                ContentType = "text/xml; charset=\"utf-8\"",                
                Content = binding.SoapResponseXml
            };
        }

        /// <summary>
        /// To XML Action Result
        /// </summary>
        public static IActionResult ToActionResult(this Saml2Metadata metadata)
        {
            return new ContentResult
            {
                ContentType = "text/xml",
                Content = metadata.ToXml(),
            };
        }
    }
}
