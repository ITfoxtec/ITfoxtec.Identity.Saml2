using ITfoxtec.Identity.Saml2.Schemas;
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
        public static Http.HttpRequest ToGenericHttpRequest(this HttpRequestBase request, bool readBodyAsString = false, bool validate = false)
        {
            var samlHttpRequest = new Http.HttpRequest
            {
                Method = request.HttpMethod,
                QueryString = request.Url.Query,
                Query = request.QueryString,
                Form = "POST".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase) ? request.Form : null,
                Body = ReadBody(request, readBodyAsString)
            };

            if (validate)
            {
                var length = 0;
                if (!string.IsNullOrEmpty(samlHttpRequest.QueryString))
                {
                    length += samlHttpRequest.QueryString.Length;
                }
                if (readBodyAsString)
                {
                    if (!string.IsNullOrEmpty(samlHttpRequest.Body))
                    {
                        length += samlHttpRequest.Body.Length;
                    }
                }
                else
                {
                    if (samlHttpRequest.Form != null)
                    {
                        foreach (string item in samlHttpRequest.Form)
                        {
                            if (!string.IsNullOrEmpty(item))
                            {
                                length += item.Length;
                            }
                        }
                    }
                }
                if (length > Saml2Constants.RequestResponseMaxLength)
                {
                    throw new Saml2RequestException($"Invalid SAML 2.0 request/response with a length of {length}, max length {Saml2Constants.RequestResponseMaxLength}.");
                }
            }
            return samlHttpRequest;
        }

        private static string ReadBody(HttpRequestBase request, bool readBodyAsString)
        {
            if (!readBodyAsString)
            {
                return null;
            }

            using (var reader = new StreamReader(request.InputStream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
