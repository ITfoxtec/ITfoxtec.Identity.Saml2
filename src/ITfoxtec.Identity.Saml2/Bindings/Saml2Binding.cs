using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
#if DEBUG
using System.Diagnostics;
#endif

namespace ITfoxtec.Identity.Saml2
{
    public abstract class Saml2Binding
    {
        public XmlDocument XmlDocument { get; protected set; }

        public string SignatureAlgorithm { get; protected set; }

        public string XmlCanonicalizationMethod { get; protected set; }

        /// <summary>
        /// <para>Sets the relaystate of the message.</para>
        /// <para>If the message being built is a response message, the relaystate will be included unmodified.</para>
        /// <para>If the message being built is a request message, the relaystate will be encoded and compressed before being included.</para>
        /// </summary>
        public string RelayState { get; set; }

        public Saml2Binding()
        { }

        protected virtual void BindInternal(Saml2Request saml2RequestResponse, bool createXml = true)
        {
            if (saml2RequestResponse == null)
                throw new ArgumentNullException(nameof(saml2RequestResponse));

            if (saml2RequestResponse.Config == null)
                throw new ArgumentNullException("saml2RequestResponse.Config");

            if (saml2RequestResponse.Config.SigningCertificate != null)
            {
                if (saml2RequestResponse.Config.SigningCertificate.GetSamlRSAPrivateKey() == null)
                {
                    throw new ArgumentException("No RSA Private Key present in Signing Certificate or missing private key read credentials.");
                }
            }

            if (createXml)
            {
                XmlDocument = saml2RequestResponse.ToXml();

#if DEBUG
                Debug.WriteLine("Saml2P: " + XmlDocument.OuterXml);
#endif
            }
        }

        internal void ApplyBinding(Saml2Request saml2RequestResponse, string messageName)
        {
            BindInternal(saml2RequestResponse, messageName);
        }

        protected abstract void BindInternal(Saml2Request saml2RequestResponse, string messageName);

        public Saml2Request Unbind(HttpRequest request, Saml2Request saml2Request)
        {
            return UnbindInternal(request, saml2Request, Saml2Constants.Message.SamlRequest);
        }

        public Saml2Response Unbind(HttpRequest request, Saml2Response saml2Response)
        {
            return UnbindInternal(request, saml2Response, Saml2Constants.Message.SamlResponse) as Saml2Response;
        }

        public Saml2ArtifactResolve Unbind(HttpRequest request, Saml2ArtifactResolve saml2ArtifactResolve)
        {
            return UnbindInternal(request, saml2ArtifactResolve, Saml2Constants.Message.SamlArt) as Saml2ArtifactResolve;
        }

        protected Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2RequestResponse)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (saml2RequestResponse == null)
                throw new ArgumentNullException(nameof(saml2RequestResponse));

            if (saml2RequestResponse.Config == null)
                throw new ArgumentNullException("saml2RequestResponse.Config");

            SetSignatureValidationCertificates(saml2RequestResponse);

            return saml2RequestResponse;
        }

        protected void SetSignatureValidationCertificates(Saml2Request saml2RequestResponse)
        {
            if (saml2RequestResponse.SignatureValidationCertificates == null || saml2RequestResponse.SignatureValidationCertificates.Count() < 1)
                saml2RequestResponse.SignatureValidationCertificates = saml2RequestResponse.Config.SignatureValidationCertificates;
            if (saml2RequestResponse.SignatureAlgorithm == null)
                saml2RequestResponse.SignatureAlgorithm = saml2RequestResponse.Config.SignatureAlgorithm;
            if (saml2RequestResponse.XmlCanonicalizationMethod == null)
                saml2RequestResponse.XmlCanonicalizationMethod = saml2RequestResponse.Config.XmlCanonicalizationMethod;

            if (saml2RequestResponse.SignatureValidationCertificates != null && saml2RequestResponse.SignatureValidationCertificates.Count(c => c.GetRSAPublicKey() == null) > 0)
                throw new ArgumentException("No RSA Public Key present in at least Signature Validation Certificate.");
        }

        protected abstract Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2RequestResponse, string messageName);

        public Saml2Request ReadSamlRequest(HttpRequest request, Saml2Request saml2Request)
        {
            return Read(request, saml2Request, Saml2Constants.Message.SamlRequest, false, false);
        }

        public Saml2Request ReadSamlResponse(HttpRequest request, Saml2Response saml2Response)
        {
            return Read(request, saml2Response, Saml2Constants.Message.SamlResponse, false, false);
        }

        public Saml2Request ReadSamlResponse(HttpRequest request, Saml2ArtifactResolve saml2ArtifactResolve)
        {
            return Read(request, saml2ArtifactResolve, Saml2Constants.Message.SamlArt, false, false);
        }


        protected abstract Saml2Request Read(HttpRequest request, Saml2Request saml2RequestResponse, string messageName, bool validate, bool detectReplayedTokens);

        public bool IsRequest(HttpRequest request)
        {
            return IsRequestResponseInternal(request, Saml2Constants.Message.SamlRequest);
        }

        public bool IsResponse(HttpRequest request)
        {
            return IsRequestResponseInternal(request, Saml2Constants.Message.SamlResponse);
        }

        protected abstract bool IsRequestResponseInternal(HttpRequest request, string messageName);
    }
}
