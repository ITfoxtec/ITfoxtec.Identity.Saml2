using System.Collections.Specialized;
using System.Linq;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
using System;
using System.IO;
using System.Threading.Tasks;

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
        public static Http.HttpRequest ToGenericHttpRequest(this HttpRequest request)
        {
            return new Http.HttpRequest
            {
                Method = request.Method,
                QueryString = request.QueryString.Value,
                Query = ToNameValueCollection(request.Query),
                Form = "POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase) ? ToNameValueCollection(request.Form) : null
            };
        }

        /// <summary>
        /// Converts a Microsoft.AspNet.Http.HttpRequest to ITfoxtec.Identity.Saml2.Http.HttpRequest.
        /// </summary>
        public static async Task<Http.HttpRequest> ToGenericHttpRequestAsync(this HttpRequest request, bool readBodyAsString = false)
        {
            if (readBodyAsString)
            {
                return new Http.HttpRequest
                {
                    Method = request.Method,
                    Body = await ReadBodyStringAsync(request)
                };
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
