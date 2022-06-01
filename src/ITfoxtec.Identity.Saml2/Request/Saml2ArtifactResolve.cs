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
using System.Threading;
using ITfoxtec.Identity.Saml2.Configuration;
using System.Linq;
using ITfoxtec.Identity.Saml2.Util;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Artifact Resolve.
    /// </summary>
    public class Saml2ArtifactResolve<T> : Saml2Request where T : Saml2Request
    {
        const string elementName = Saml2Constants.Message.ArtifactResolve;

#if NET || NETCORE
        private readonly IHttpClientFactory httpClientFactory;
#else
        private readonly HttpClient httpClient;
#endif

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

        public Saml2ArtifactResolve(
#if NET || NETCORE
            IHttpClientFactory httpClientFactory,
#else
            HttpClient httpClient,
#endif
            Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

#if NET || NETCORE
            this.httpClientFactory = httpClientFactory;
#else
            this.httpClient = httpClient;
#endif  

            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
            if (config.ArtifactResolutionService is null || config.ArtifactResolutionService.Location is null)
            {
                throw new Saml2ConfigurationException("The ArtifactResolutionService is required to be configured.");
            }
            Destination = config.ArtifactResolutionService.Location;
        }

        /// <summary>
        /// Create SAML V2.0 defined artifact type of type code 0x0004.
        /// </summary>
        internal void CreateArtifact()
        {
            var artifactBytes = new byte[44];
            artifactBytes[1] = 4; // 0x0004

            artifactBytes[2] = (byte)(Config.ArtifactResolutionService.Index >> 8);
            artifactBytes[3] = (byte)Config.ArtifactResolutionService.Index;

            if (string.IsNullOrEmpty(Issuer)) throw new ArgumentNullException("Issuer property");
            Array.Copy(Issuer.ComputeSha1Hash(), 0, artifactBytes, 4, 20);

            Array.Copy(RandomGenerator.GenerateArtifactMessageHandle(), 0, artifactBytes, 24, 20);

            Artifact = Uri.EscapeDataString(Convert.ToBase64String(artifactBytes));
        }

        internal void ValidateArtifact()
        {
            if (Config.ValidateArtifact)
            {
                var artifactBytes = Convert.FromBase64String(Artifact);

                if (string.IsNullOrEmpty(Config.AllowedIssuer))
                {
                    throw new Saml2ConfigurationException("Unable to validate Artifact SourceId/Issuer. AllowedIssuer not configured.");
                }
                var sourceIdBytes = new byte[20];
                Array.Copy(artifactBytes, 4, sourceIdBytes, 0, 20);
                if (!sourceIdBytes.SequenceEqual(Config.AllowedIssuer.ComputeSha1Hash()))
                {
                    throw new Saml2RequestException($"Invalid SourceId/Issuer. Actually '{Issuer}', allowed '{Config.AllowedIssuer}'");
                }

                var arsIndex = (artifactBytes[2] << 8) | artifactBytes[3];
                if (arsIndex != Config.ArtifactResolutionService.Index)
                {
                    throw new Saml2RequestException($"Invalid ArtifactResolutionService Index. Actually '{arsIndex}', expected '{Config.ArtifactResolutionService.Index}'");
                }
            }
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

        public async Task ResolveAsync(T saml2Request, CancellationToken? cancellationToken = null)
        {
#if NET || NETCORE
            var httpClient = httpClientFactory.CreateClient();
#endif            

            var soapEnvelope = new Saml2SoapEnvelope<T>(this);          
            var content = new StringContent(soapEnvelope.ToSoapXml().OuterXml, Encoding.UTF8, "text/xml; charset=\"utf-8\"");
            content.Headers.Add("SOAPAction", "\"http://www.oasis-open.org/committees/security\"");
            using (var response = cancellationToken.HasValue ? await httpClient.PostAsync(Destination, content, cancellationToken.Value) : await httpClient.PostAsync(Destination, content))
            {
                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
#if NET
                        var result = cancellationToken.HasValue ? await response.Content.ReadAsStringAsync(cancellationToken.Value) : await response.Content.ReadAsStringAsync();
#else
                        var result = await response.Content.ReadAsStringAsync();
#endif
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
