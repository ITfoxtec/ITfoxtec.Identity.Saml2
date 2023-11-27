using System.Collections.Specialized;
using System.Linq;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
using System;
using System.IO;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2.MvcCore
{
    /// <summary>
    /// Extension methods for HttpRequest
    /// </summary>
    public static class HttpRequestExtensions
    {
        /// <summary>
        /// Converts a Microsoft.AspNet.Http.HttpRequest to ITfoxtec.Identity.Saml2.Http.HttpRequest.
        /// </summary>
        public static Http.HttpRequest ToGenericHttpRequest(this HttpRequest request, bool validate = false)
        {
            var samlHttpRequest = new Http.HttpRequest
            {
                Method = request.Method,
                QueryString = request.QueryString.Value,
                Query = ToNameValueCollection(request.Query),
            };

            if("POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                samlHttpRequest.Form = ToNameValueCollection(request.Form);
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
                if (length > Saml2Constants.RequestResponseMaxLength)
                {
                    throw new Saml2RequestException($"Invalid SAML 2.0 request/response with a length of {length}, max length {Saml2Constants.RequestResponseMaxLength}.");
                }
            }
            return samlHttpRequest;
        }

        /// <summary>
        /// Converts a Microsoft.AspNet.Http.HttpRequest to ITfoxtec.Identity.Saml2.Http.HttpRequest.
        /// </summary>
        public static async Task<Http.HttpRequest> ToGenericHttpRequestAsync(this HttpRequest request, bool readBodyAsString = false, bool validate = false)
        {
            if (readBodyAsString)
            {
                var samlHttpRequest = new Http.HttpRequest
                {
                    Method = request.Method,
                    Body = await ReadBodyStringAsync(request)
                };

                if (validate)
                {
                    if (!string.IsNullOrEmpty(samlHttpRequest.Body))
                    {
                        var length = samlHttpRequest.Body.Length;
                        if (length > Saml2Constants.RequestResponseMaxLength)
                        {
                            throw new Saml2RequestException($"Invalid SAML 2.0 request/response with a length of {length}, max length {Saml2Constants.RequestResponseMaxLength}.");
                        }
                    }
                }
                return samlHttpRequest;
            }
            else
            {
                return ToGenericHttpRequest(request);
            }
        }

        private static NameValueCollection ToNameValueCollection(IEnumerable<KeyValuePair<string, StringValues>> items)
        {
            var nv = new NameValueCollection();
            foreach (var item in items)
            {
                nv.Add(item.Key, item.Value.First());
            }
            return nv;
        }

        private static async Task<string> ReadBodyStringAsync(HttpRequest request)
        {
            using (var reader = new StreamReader(request.Body))
            {
                return await reader.ReadToEndAsync();
            }
        }
    }
}
