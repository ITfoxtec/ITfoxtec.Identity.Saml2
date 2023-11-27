using ITfoxtec.Identity.Saml2.Schemas;
using System.Web;
using System;
using System.IO;
using System.Linq;

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
                Body = ReadBody(request, readBodyAsString)
            };

            if ("POST".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase))
            {
                samlHttpRequest.Form = request.Form;
                samlHttpRequest.Binding = new Saml2PostBinding();
            }
            else
            {
                if (samlHttpRequest.Query.AllKeys.Contains(Saml2Constants.Message.SamlArt))
                {
                    samlHttpRequest.Binding = new Saml2ArtifactBinding();
                }
                else
                {
                    samlHttpRequest.Binding = new Saml2RedirectBinding();
                }
            }

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
