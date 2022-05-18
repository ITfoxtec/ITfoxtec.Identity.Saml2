using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Http;
using System.Net;
using System.IO;
using System.IO.Compression;
using ITfoxtec.Identity.Saml2.Cryptography;

namespace ITfoxtec.Identity.Saml2.Bindings
{
    public class Saml2ArtifactBinding : Saml2Binding<Saml2ArtifactBinding>
    {
        public enum BindingProtocol
        {
            Get = 10,
            Post = 20
        }

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// [Optional]
        /// Set bind protocol, default HTTP GET. Unbind and read default support both HTTP GET and HTTP POST.
        /// </summary>
        public BindingProtocol BindProtocol { get; set; } = BindingProtocol.Get;

        public Uri RedirectLocation { get; protected set; }

        public string Signature { get; protected set; }

        /// <summary>
        /// HTTP post content.
        /// </summary>
        public string PostContent { get; set; }

        public Saml2ArtifactBinding()
        {
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        protected override Saml2ArtifactBinding BindInternal(Saml2Request saml2ArtifactResolve, string messageName)
        {
            if (BindProtocol == BindingProtocol.Get)
            {                
                return BindGetInternal(saml2ArtifactResolve as Saml2ArtifactResolve, messageName);
            }
            else if (BindProtocol == BindingProtocol.Post)
            {
                return BindPostInternal(saml2ArtifactResolve as Saml2ArtifactResolve, messageName);
            }
            else
            {
                throw new InvalidOperationException("Invalid BindProtocol.");
            }
        }

        private Saml2ArtifactBinding BindGetInternal(Saml2ArtifactResolve saml2ArtifactResolve, string messageName)
        {
            base.BindInternal(saml2ArtifactResolve);

            Cryptography.SignatureAlgorithm.ValidateAlgorithm(saml2ArtifactResolve.Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(saml2ArtifactResolve.Config.XmlCanonicalizationMethod);
            SignatureAlgorithm = saml2ArtifactResolve.Config.SignatureAlgorithm;
            XmlCanonicalizationMethod = saml2ArtifactResolve.Config.XmlCanonicalizationMethod;

            var requestQueryString = string.Join("&", RequestQueryString(saml2ArtifactResolve, messageName));
            requestQueryString = SigneQueryString(requestQueryString, saml2ArtifactResolve.Config.SigningCertificate);

            RedirectLocation = new Uri(string.Join(saml2ArtifactResolve.Destination.OriginalString.Contains('?') ? "&" : "?", saml2ArtifactResolve.Destination.OriginalString, requestQueryString));

            return this;
        }

        private string SigneQueryString(string queryString, X509Certificate2 signingCertificate)
        {
            var saml2Signed = new Saml2SignedText(signingCertificate, SignatureAlgorithm);
            Signature = Convert.ToBase64String(saml2Signed.SignData(Encoding.UTF8.GetBytes(queryString)));

            return string.Join("&", queryString, string.Join("=", Saml2Constants.Message.Signature, Uri.EscapeDataString(Signature)));
        }

        private IEnumerable<string> RequestQueryString(Saml2Request saml2RequestResponse, string messageName)
        {
            yield return string.Join("=", messageName, Uri.EscapeDataString(CompressRequest()));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, Uri.EscapeDataString(RelayState));
            }

            if ((!(saml2RequestResponse is Saml2AuthnRequest) || saml2RequestResponse.Config.SignAuthnRequest) && saml2RequestResponse.Config.SigningCertificate != null)
            {
                yield return string.Join("=", Saml2Constants.Message.SigAlg, Uri.EscapeDataString(SignatureAlgorithm));
            }
        }

        private string CompressRequest()
        {
            using (var compressedStream = new MemoryStream())
            using (var deflateStream = new DeflateStream(compressedStream, CompressionMode.Compress))
            {
                using (var originalStream = new StreamWriter(deflateStream))
                {
                    originalStream.Write(XmlDocument.OuterXml);
                }

                return Convert.ToBase64String(compressedStream.ToArray());
            }
        }


        private Saml2ArtifactBinding BindPostInternal(Saml2ArtifactResolve saml2ArtifactResolve, string messageName)
        {
            BindInternal(saml2ArtifactResolve);

            Cryptography.SignatureAlgorithm.ValidateAlgorithm(saml2ArtifactResolve.Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(saml2ArtifactResolve.Config.XmlCanonicalizationMethod);
            XmlDocument = XmlDocument.SignDocument(saml2ArtifactResolve.Config.SigningCertificate, saml2ArtifactResolve.Config.SignatureAlgorithm, saml2ArtifactResolve.Config.XmlCanonicalizationMethod, CertificateIncludeOption, saml2ArtifactResolve.IdAsString);

            PostContent = string.Concat(HtmlPostPage(saml2ArtifactResolve.Destination, messageName));
            return this;
        }

        private IEnumerable<string> HtmlPostPage(Uri destination, string messageName)
        {
            yield return string.Format(
@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8"" />
    <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"" />
    <title>SAML 2.0</title>
</head>
<body onload=""document.forms[0].submit()"">
    <noscript>
        <p>
            <strong>Note:</strong> Since your browser does not support JavaScript, 
            you must press the Continue button once to proceed.
        </p>
    </noscript>
    <form action=""{0}"" method=""post"">
        <div>", destination);

            yield return string.Format(
@"<input type=""hidden"" name=""{0}"" value=""{1}""/>", messageName, Convert.ToBase64String(Encoding.UTF8.GetBytes(XmlDocument.OuterXml)));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Format(
@"<input type=""hidden"" name=""{0}"" value=""{1}""/>", Saml2Constants.Message.RelayState, WebUtility.HtmlEncode(RelayState));
            }

            yield return
@"</div>
        <noscript>
            <div>
                <input type=""submit"" value=""Continue""/>
            </div>
        </noscript>
    </form>
</body>
</html>";
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
            if (!(saml2ArtifactResolve is Saml2ArtifactResolve))
                throw new ArgumentException("Saml2Request is not a Saml2ArtifactResolve");

            if ("GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadGet(request, saml2ArtifactResolve as Saml2ArtifactResolve, messageName, validateXmlSignature, detectReplayedTokens);
            }
            else if ("POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
            {
                return ReadPost(request, saml2ArtifactResolve as Saml2ArtifactResolve, messageName, validateXmlSignature, detectReplayedTokens);
            }
            else
                throw new InvalidSaml2BindingException("Not HTTP GET or HTTP POST Method.");
        }

        private Saml2Request ReadGet(HttpRequest request, Saml2ArtifactResolve saml2ArtifactResolve, string messageName, bool validateXmlSignature, bool detectReplayedTokens)
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

        private Saml2Request ReadPost(HttpRequest request, Saml2ArtifactResolve saml2ArtifactResolve, string messageName, bool validateXmlSignature, bool detectReplayedTokens)
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
