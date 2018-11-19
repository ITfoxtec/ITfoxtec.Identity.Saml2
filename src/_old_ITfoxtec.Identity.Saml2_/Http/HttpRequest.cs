using System.Collections.Specialized;

namespace ITfoxtec.Identity.Saml2.Http
{
    public class HttpRequest
    {
        /// <summary>
        /// Gets or set the HTTP Method.
        /// </summary>
        public string Method { get; set; }

        /// <summary>
        /// Gets or set the Raw Query String.
        /// </summary>
        public string QueryString { get; set; }

        /// <summary>
        /// Gets or set the Query value collection.
        /// </summary>
        public NameValueCollection Query { get; set; }

        /// <summary>
        /// Gets or set the Request Body as a Form value collection.
        /// </summary>
        public NameValueCollection Form { get; set; }

    }
}
