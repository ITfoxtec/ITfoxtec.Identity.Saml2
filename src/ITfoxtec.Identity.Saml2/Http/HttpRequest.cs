using System.Collections.Specialized;

namespace ITfoxtec.Identity.Saml2.Http
{
    public class HttpRequest
    {
        /// <summary>
        /// Get or set the HTTP method.
        /// </summary>
        public string Method { get; set; }

        /// <summary>
        /// Get or set the SAML 2.0 redirect or POST binding.
        /// </summary>
        public Saml2Binding Binding { get; set; }

        /// <summary>
        /// Get or set the Raw Query string.
        /// </summary>
        public string QueryString { get; set; }

        /// <summary>
        /// Get or set the Query value collection.
        /// </summary>
        public NameValueCollection Query { get; set; }

        /// <summary>
        /// Get or set the request body as a Form value collection.
        /// </summary>
        public NameValueCollection Form { get; set; }

        /// <summary>
        /// Get or set the request body as a string.
        /// </summary>
        public string Body { get; set; }
    }
}
