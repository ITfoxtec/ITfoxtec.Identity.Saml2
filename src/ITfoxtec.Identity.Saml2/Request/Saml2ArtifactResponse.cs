using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2ArtifactResponse : Saml2Response
    {
        public override string ElementName => Saml2Constants.Message.ArtifactResponse;

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        public Saml2Request InnerRequest { get; set; }

        public Saml2ArtifactResponse(Saml2Configuration config, Saml2Request request) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            CertificateIncludeOption = X509IncludeOption.EndCertOnly;

            InnerRequest = request;
            InnerRequest.Destination = null;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + ElementName);
            envelope.Add(base.GetXContent());
            XmlDocument = envelope.ToXmlDocument();

            var innerRequestXml = InnerRequest.ToXml();
            var status = XmlDocument.DocumentElement[Saml2Constants.Message.Status, Saml2Constants.ProtocolNamespace.OriginalString];
            XmlDocument.DocumentElement.InsertAfter(XmlDocument.ImportNode(innerRequestXml.DocumentElement, true), status);
            
            if (Config.SigningCertificate != null)
            {
                SignArtifactResponse();
            }
            return XmlDocument;
        }

        protected internal void SignArtifactResponse()
        {
            Cryptography.SignatureAlgorithm.ValidateAlgorithm(Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(Config.XmlCanonicalizationMethod);
            XmlDocument = XmlDocument.SignDocument(Config.SigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, CertificateIncludeOption, Id.Value);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new Saml2RequestException("Not a SAML2 Artifact Response.");
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            if (Status == Saml2StatusCodes.Success)
            {
                InnerRequest.Read(GetInnerArtifactResponseXml(InnerRequest.ElementName), false, false);
            }
        }

        private string GetInnerArtifactResponseXml(string innerElementName)
        {
            var innerElements = XmlDocument.DocumentElement.SelectNodes(string.Format("//*[local-name()='{0}']", innerElementName));
            if (innerElements.Count != 1)
            {
                throw new Saml2RequestException("There is not exactly one inner artifact response element.");
            }
            return innerElements[0].OuterXml;
        }
    }
}
