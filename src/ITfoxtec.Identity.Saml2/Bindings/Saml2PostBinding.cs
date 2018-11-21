using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Http;
using System.Net;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2PostBinding : Saml2Binding<Saml2PostBinding>
    {
        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// Html post content.
        /// </summary>
        public string PostContent { get; set; }

        public Saml2PostBinding()
        {
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        protected override Saml2PostBinding BindInternal(Saml2Request saml2RequestResponse, string messageName)
        {
            BindInternal(saml2RequestResponse);

            if ((!(saml2RequestResponse is Saml2AuthnRequest) || saml2RequestResponse.Config.SignAuthnRequest) && saml2RequestResponse.Config.SigningCertificate != null)
            {
                Cryptography.SignatureAlgorithm.ValidateAlgorithm(saml2RequestResponse.Config.SignatureAlgorithm);
                XmlDocument = XmlDocument.SignDocument(saml2RequestResponse.Config.SigningCertificate, saml2RequestResponse.Config.SignatureAlgorithm, CertificateIncludeOption, saml2RequestResponse.IdAsString);
            }

            PostContent = string.Concat(HtmlPostPage(saml2RequestResponse.Destination, messageName));
            return this;
        }

        private IEnumerable<string> HtmlPostPage(Uri destination, string messageName)
        {
            yield return string.Format(
@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8"" />
    <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"">
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

        protected override Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2RequestResponse, string messageName)
        {
            UnbindInternal(request, saml2RequestResponse);

            if (!"POST".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not HTTP POST Method.");

            if (!request.Form.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Form does not contain " + messageName);

            return Read(request, saml2RequestResponse, messageName, true);
        }

        protected override Saml2Request Read(HttpRequest request, Saml2Request saml2RequestResponse, string messageName, bool validateXmlSignature)
        {
            if (request.Form.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Form[Saml2Constants.Message.RelayState];
            }

            saml2RequestResponse.Read(Encoding.UTF8.GetString(Convert.FromBase64String(request.Form[messageName])), validateXmlSignature);
            XmlDocument = saml2RequestResponse.XmlDocument;
            return saml2RequestResponse;
        }
    }
}
