using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2ArtifactResponse : Saml2Response
    {
        public override string ElementName => Schemas.Saml2Constants.Message.ArtifactResponse;

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
            var envelope = new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + ElementName);
            envelope.Add(base.GetXContent());
            XmlDocument = envelope.ToXmlDocument();

            var innerRequestXml = InnerRequest.ToXml();
            var status = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Status, Schemas.Saml2Constants.ProtocolNamespace.OriginalString];
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

            if (Status == Schemas.Saml2StatusCodes.Success)
            {
                InnerRequest.Read(GetInnerArtifactElementXml().OuterXml, false, false);
            }
        }

        XmlElement assertionElementCache = null;
        protected override XmlElement GetAssertionElement()
        {
            if (assertionElementCache == null)
            {
                if (Status == Schemas.Saml2StatusCodes.Success && InnerRequest is Saml2AuthnResponse)
                {
#if NETFULL || NETSTANDARD || NETCORE || NET50 || NET60
                    assertionElementCache = GetAssertionElementReference().ToXmlDocument().DocumentElement;
#else
                    assertionElementCache = GetAssertionElementReference();
#endif
                }
            }
            return assertionElementCache;
        }

        private XmlElement GetAssertionElementReference()
        {
            var assertionElements = GetInnerArtifactElementXml().SelectNodes($"//*[local-name()='{Schemas.Saml2Constants.Message.Assertion}']");
            if (assertionElements.Count != 1)
            {
                throw new Saml2RequestException("There is not exactly one Assertion element in the inner Artifact element.");
            }
            return assertionElements[0] as XmlElement;
        }

        XmlNode innerArtifactElementCache = null;
        private XmlNode GetInnerArtifactElementXml()
        {
            if (innerArtifactElementCache == null)
            {
                var innerElements = XmlDocument.DocumentElement.SelectNodes(string.Format("//*[local-name()='{0}']", InnerRequest.ElementName));
                if (innerElements?.Count != 1)
                {
                    throw new Saml2RequestException("There is not exactly one inner artifact element.");
                }
                innerArtifactElementCache = innerElements[0];
            }

            return innerArtifactElementCache;
        }
    }
}
