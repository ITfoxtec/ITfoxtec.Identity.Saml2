using System.Collections.Specialized;
using System.IO;

namespace ITfoxtec.Identity.Saml2.Http
{
    public class HttpRequest
    {
        /// <summary>
        /// Gets or set the HTTP method.
        /// </summary>
        public string Method { get; set; }

        /// <summary>
        /// Gets or set the Raw Query string.
        /// </summary>
        public string QueryString { get; set; }

        /// <summary>
        /// Gets or set the Query value collection.
        /// </summary>
        public NameValueCollection Query { get; set; }

        /// <summary>
        /// Gets or set the request body as a Form value collection.
        /// </summary>
        public NameValueCollection Form { get; set; }

        /// <summary>
        /// Gets or set the request body as a string.
        /// </summary>
        public string Body { get; set; }
    }
}
