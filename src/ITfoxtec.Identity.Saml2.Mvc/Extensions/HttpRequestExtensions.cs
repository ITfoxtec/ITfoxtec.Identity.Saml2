using System.Web;
using System;
using System.IO;

namespace ITfoxtec.Identity.Saml2.Mvc
{
    /// <summary>
    /// Extension methods for HttpRequest
    /// </summary>
    public static class HttpRequestExtensions
    {
        /// <summary>
        /// Converts a System.Web.HttpRequestBase to ITfoxtec.Identity.Saml2.Http.HttpRequest.
        /// </summary>
        public static Http.HttpRequest ToGenericHttpRequest(this HttpRequestBase request, bool readBodyAsString = false)
        {
            return new Http.HttpRequest
            {
                Method = request.HttpMethod,
                QueryString = request.Url.Query,
                Query = request.QueryString,
                Form = "POST".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase) ? request.Form : null,
                Body = ReadBody(request, readBodyAsString)
            };
        }

        private static string ReadBody(HttpRequestBase request, bool readBodyAsString)
        {
            if (!readBodyAsString)
            {
                return null;
            }

            try
            {
                using (var reader = new StreamReader(request.InputStream))
                {
                    return reader.ReadToEnd();
                }
            }
            finally
            {
                request.InputStream.Position = 0;
            }
        }
    }
}
