using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Http;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2ArtifactBinding<T> : Saml2Binding<Saml2ArtifactBinding<T>> where T : Saml2Request
    {
        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        public Uri RedirectLocation { get; protected set; }

        public Saml2ArtifactBinding()
        {
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        protected override Saml2ArtifactBinding<T> BindInternal(Saml2Request saml2ArtifactResolve, string messageName)
        {
            base.BindInternal(saml2ArtifactResolve);

            if (!(saml2ArtifactResolve is Saml2ArtifactResolve<T>))
                throw new ArgumentException("Saml2Request is not a Saml2ArtifactResolve");

            var requestQueryString = string.Join("&", RequestQueryString(saml2ArtifactResolve as Saml2ArtifactResolve<T>, messageName));
            RedirectLocation = new Uri(string.Join(saml2ArtifactResolve.Destination.OriginalString.Contains('?') ? "&" : "?", saml2ArtifactResolve.Destination.OriginalString, requestQueryString));

            return this;
        }

        private IEnumerable<string> RequestQueryString(Saml2ArtifactResolve<T> saml2ArtifactResolve, string messageName)
        {
            yield return string.Join("=", messageName, Uri.EscapeDataString(saml2ArtifactResolve.Artifact));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, Uri.EscapeDataString(RelayState));
            }
        }

        protected override Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2ArtifactResolve, string messageName)
        {
            UnbindInternal(request, saml2ArtifactResolve);

            return Read(request, saml2ArtifactResolve, messageName, true, true);
        }

        /// <summary>
        /// SAML Bindings 2.0 - 3.6.3 Message Encoding
        /// There are two methods of encoding an artifact for use with this binding.One is to encode the artifact into a
        /// URL parameter and the other is to place the artifact in an HTML form control.When URL encoding is
        /// used, the HTTP GET method is used to deliver the message, while POST is used with form encoding. 
        /// All endpoints that support this binding MUST support both techniques.
        /// </summary>
        protected override Saml2Request Read(HttpRequest request, Saml2Request saml2ArtifactResolve, string messageName, bool validateXmlSignature, bool detectReplayedTokens)
        {
            if (!(saml2ArtifactResolve is Saml2ArtifactResolve<T>))
                throw new ArgumentException("Saml2Request is not a Saml2ArtifactResolve");

            if ("GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadGet(request, saml2ArtifactResolve as Saml2ArtifactResolve<T>, messageName, validateXmlSignature, detectReplayedTokens);
            }
            else if ("POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadPost(request, saml2ArtifactResolve as Saml2ArtifactResolve<T>, messageName, validateXmlSignature, detectReplayedTokens);
            }
            else
                throw new InvalidSaml2BindingException("Not HTTP GET or HTTP POST Method.");
        }

        private Saml2Request ReadGet(HttpRequest request, Saml2ArtifactResolve<T> saml2ArtifactResolve, string messageName, bool validateXmlSignature, bool detectReplayedTokens)
        {
            if (!request.Query.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Query String does not contain " + messageName);

            if (request.Query.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Query[Saml2Constants.Message.RelayState];
            }

            saml2ArtifactResolve.Artifact = request.Query[messageName];
            return saml2ArtifactResolve;
        }

        private Saml2Request ReadPost(HttpRequest request, Saml2ArtifactResolve<T> saml2ArtifactResolve, string messageName, bool validateXmlSignature, bool detectReplayedTokens)
        {
            if (!request.Form.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Form does not contain " + messageName);

            if (request.Form.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Form[Saml2Constants.Message.RelayState];
            }

            saml2ArtifactResolve.Artifact = request.Form[messageName];
            return saml2ArtifactResolve;
        }

        protected override bool IsRequestResponseInternal(HttpRequest request, string messageName)
        {
            if ("GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return (request.Query?.AllKeys?.Contains(messageName)).GetValueOrDefault(false);
            }
            else if ("POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return (request.Form?.AllKeys?.Contains(messageName)).GetValueOrDefault(false);
            }
            else
                throw new InvalidSaml2BindingException("Not HTTP GET or HTTP POST Method.");

            
        }
    }
}
