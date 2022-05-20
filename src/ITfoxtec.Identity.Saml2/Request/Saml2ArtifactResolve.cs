using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Artifact Resolve.
    /// </summary>
    public class Saml2ArtifactResolve<T> : Saml2Request where T : Saml2Request
    {
        const string elementName = Saml2Constants.Message.ArtifactResolve;

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// [Required]
        /// The artifact value that the requester received and now wishes to translate into the protocol message it
        /// represents. See [SAMLBind] for specific artifact format information.
        /// </summary>
        public string Artifact { get; set; }

        public Saml2ArtifactResolve(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
            Destination = config.ArtifactResolutionService;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            if (Config.SigningCertificate != null)
            {
                SignArtifactResolve();
            }
            return XmlDocument;
        }

        protected internal void SignArtifactResolve()
        {
            Cryptography.SignatureAlgorithm.ValidateAlgorithm(Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(Config.XmlCanonicalizationMethod);
            XmlDocument = XmlDocument.SignDocument(Config.SigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, CertificateIncludeOption, Id.Value);
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            yield return new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.Artifact, Artifact);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2RequestException("Not a SAML2 Artifact Resolve Request.");
            }
        }

        public async Task ResolveAsync(
#if NET || NETCORE
            IHttpClientFactory httpClientFactory,
#else
            HttpClient httpClient,
#endif
            T saml2Request)
        {
            var soapEnvelope = new Saml2SoapEnvelope<T>(this);

#if NET || NETCORE
            var httpClient = httpClientFactory.CreateClient();
#endif            
          
            var content = new StringContent(soapEnvelope.ToSoapXml().OuterXml, Encoding.UTF8, "text/xml; charset=\"utf-8\"");
            content.Headers.Add("SOAPAction", "\"http://www.oasis-open.org/committees/security\"");
            using (var response = await httpClient.PostAsync(Destination, content))
            {
                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                        var result = await response.Content.ReadAsStringAsync();
                        soapEnvelope.FromSoapXml(result);

                        var ares = new Saml2ArtifactResponse<T>(Config, saml2Request);
                        ares.Read(soapEnvelope.ResponseBody.OuterXml, true);
                        break;

                    default:
                        throw new Exception($"Error, Status Code OK expected. StatusCode '{response.StatusCode}'. Artifact resolve destination '{Destination}'.");
                }
            }
        }
    }
}
