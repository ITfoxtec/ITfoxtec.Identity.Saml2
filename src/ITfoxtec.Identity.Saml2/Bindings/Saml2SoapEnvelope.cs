using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2SoapEnvelope : Saml2Binding<Saml2SoapEnvelope>
    {
        /// <summary>
        /// SOAP response XML.
        /// </summary>
        public string SoapResponseXml { get; set; }

        protected override Saml2SoapEnvelope BindInternal(Saml2Request saml2Request, string messageName)
        {
            if (!(saml2Request is Saml2ArtifactResponse))
                throw new ArgumentException("Only Saml2ArtifactResponse is supported");

            BindInternal(saml2Request);

            SoapResponseXml = ToSoapXml().OuterXml;
            return this;
        }

        protected override Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2Request, string messageName)
        {
            UnbindInternal(request, saml2Request);

            return Read(request, saml2Request, messageName, true, true);
        }

        protected override Saml2Request Read(HttpRequest request, Saml2Request saml2Request, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!(saml2Request is Saml2ArtifactResolve saml2ArtifactResolve))
                throw new ArgumentException("Only Saml2ArtifactResolve is supported");

            saml2ArtifactResolve.Read(FromSoapXml(request.Body).OuterXml, validate, detectReplayedTokens);
            XmlDocument = saml2ArtifactResolve.XmlDocument;
            return saml2ArtifactResolve;
        }

        protected override bool IsRequestResponseInternal(HttpRequest request, string messageName)
        {
            throw new NotSupportedException();
        }

        public virtual async Task ResolveAsync(
#if NET || NETCORE
            IHttpClientFactory httpClientFactory,
#else
            HttpClient httpClient,
# endif
            Saml2ArtifactResolve saml2ArtifactResolve, Saml2Request saml2Request, CancellationToken? cancellationToken = null
#if NET || NETCORE
            , string httpClientName = null) 
        {
            var httpClient = string.IsNullOrEmpty(httpClientName) ? httpClientFactory.CreateClient() : httpClientFactory.CreateClient(httpClientName);
#else
        )
        {
#endif
            if (saml2ArtifactResolve.Config.ArtifactResolutionService is null || saml2ArtifactResolve.Config.ArtifactResolutionService.Location is null)
            {
                throw new Saml2ConfigurationException("The ArtifactResolutionService is required to be configured.");
            }
            var artifactDestination = saml2ArtifactResolve.Config.ArtifactResolutionService.Location;
            saml2ArtifactResolve.Destination = artifactDestination;
            XmlDocument = saml2ArtifactResolve.ToXml();

            var content = new StringContent(ToSoapXml().OuterXml, Encoding.UTF8, "text/xml");
            content.Headers.Add("SOAPAction", "\"http://www.oasis-open.org/committees/security\"");

            using (var response = cancellationToken.HasValue ? await httpClient.PostAsync(artifactDestination, content, cancellationToken.Value) : await httpClient.PostAsync(artifactDestination, content))
            {
                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
#if NET
                        var result = cancellationToken.HasValue ? await response.Content.ReadAsStringAsync(cancellationToken.Value) : await response.Content.ReadAsStringAsync();
#else
                        var result = await response.Content.ReadAsStringAsync();
#endif

                        var ares = new Saml2ArtifactResponse(saml2ArtifactResolve.Config, saml2Request);
                        SetSignatureValidationCertificates(ares);                        
                        ares.Read(FromSoapXml(result).OuterXml, ares.SignatureValidationCertificates?.Count() > 0, true);
                        ares.Status = Saml2StatusCodes.Success;
                        break;

                    default:
                        throw new Exception($"Error, Status Code OK expected. StatusCode '{response.StatusCode}'. Artifact resolve destination '{artifactDestination?.OriginalString}'.");
                }
            }
        }

        protected virtual XmlDocument ToSoapXml()
        {
            var envelope = new XElement(Saml2Constants.SoapEnvironmentNamespaceX + Saml2Constants.Message.Envelope);

            envelope.Add(GetXContent());

            return envelope.ToXmlDocument();
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2Constants.SoapEnvironmentNamespaceNameX, Saml2Constants.SoapEnvironmentNamespace.OriginalString);
            yield return new XElement(Saml2Constants.SoapEnvironmentNamespaceX + Saml2Constants.Message.Body, XmlDocument.ToXDocument().Root);
        }

        protected virtual XmlDocument FromSoapXml(string xml)
        {
            var xmlDoc = xml.ToXmlDocument();

            var bodyList = GetNodesByLocalname(xmlDoc.DocumentElement, "Body");
            if (bodyList.Count != 1)
            {
                throw new Exception("There is not exactly one Body element.");
            }

            var faultBody = GetNodeByLocalname(bodyList[0], "Fault");
            if (faultBody != null)
            {
                var faultcode = GetNodeByLocalname(faultBody, "faultcode");
                var faultstring = GetNodeByLocalname(faultBody, "faultstring");
                throw new Saml2RequestException("SAML 2.0 Artifact SOAP error: " + faultcode + "\n" + faultstring);
            }

            return bodyList[0].InnerXml.ToXmlDocument();
        }

        private XmlNodeList GetNodesByLocalname(XmlNode xe, string localName)
        {
            return xe.SelectNodes(string.Format("//*[local-name()='{0}']", localName));
        }

        private XmlNode GetNodeByLocalname(XmlNode xe, string localName)
        {
            return xe.SelectSingleNode(string.Format("//*[local-name()='{0}']", localName));
        }
    }
}