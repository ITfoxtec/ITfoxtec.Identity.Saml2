using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Http;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2ArtifactBinding : Saml2Binding
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

        protected internal override void BindInternal(Saml2Request saml2Request, string messageName)
        {
            if (!(saml2Request is Saml2ArtifactResolve saml2ArtifactResolve))
                throw new ArgumentException("Only Saml2ArtifactResolve is supported");

            base.BindInternal(saml2ArtifactResolve, false);

            saml2ArtifactResolve.CreateArtifact();

            var requestQueryString = string.Join("&", RequestQueryString(saml2ArtifactResolve, messageName));
            RedirectLocation = new Uri(string.Join(saml2ArtifactResolve.Destination.OriginalString.Contains('?') ? "&" : "?", saml2ArtifactResolve.Destination.OriginalString, requestQueryString));
        }

        private IEnumerable<string> RequestQueryString(Saml2ArtifactResolve saml2ArtifactResolve, string messageName)
        {
            yield return string.Join("=", messageName, Uri.EscapeDataString(saml2ArtifactResolve.Artifact));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, Uri.EscapeDataString(RelayState));
            }
        }

        protected override Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2Request, string messageName)
        {
            UnbindInternal(request, saml2Request);

            return Read(request, saml2Request, messageName, true, true);
        }

        /// <summary>
        /// SAML Bindings 2.0 - 3.6.3 Message Encoding
        /// There are two methods of encoding an artifact for use with this binding.One is to encode the artifact into a
        /// URL parameter and the other is to place the artifact in an HTML form control.When URL encoding is
        /// used, the HTTP GET method is used to deliver the message, while POST is used with form encoding. 
        /// All endpoints that support this binding MUST support both techniques.
        /// </summary>
        protected override Saml2Request Read(HttpRequest request, Saml2Request saml2Request, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!(saml2Request is Saml2ArtifactResolve saml2ArtifactResolve))
                throw new ArgumentException("Only Saml2ArtifactResolve is supported");

            if ("GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadGet(request, saml2ArtifactResolve, messageName, validate, detectReplayedTokens);
            }
            else if ("POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadPost(request, saml2ArtifactResolve, messageName, validate, detectReplayedTokens);
            }
            else
                throw new InvalidSaml2BindingException("Not HTTP GET or HTTP POST Method.");
        }

        private Saml2Request ReadGet(HttpRequest request, Saml2ArtifactResolve saml2ArtifactResolve, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!request.Query.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Query String does not contain " + messageName);

            if (request.Query.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Query[Saml2Constants.Message.RelayState];
            }

            saml2ArtifactResolve.Artifact = request.Query[messageName];
            if (validate)
            {
                saml2ArtifactResolve.ValidateArtifact();
            }
            return saml2ArtifactResolve;
        }

        private Saml2Request ReadPost(HttpRequest request, Saml2ArtifactResolve saml2ArtifactResolve, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!request.Form.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Form does not contain " + messageName);

            if (request.Form.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Form[Saml2Constants.Message.RelayState];
            }

            saml2ArtifactResolve.Artifact = request.Form[messageName];
            if (validate)
            {
                saml2ArtifactResolve.ValidateArtifact();
            }
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
            {
                throw new InvalidSaml2BindingException("Not HTTP GET or HTTP POST Method.");
            }
        }
    }
}
