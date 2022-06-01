using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Xml;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2ArtifactResponse<T> : Saml2Response where T : Saml2Request
    {
        const string elementName = Saml2Constants.Message.ArtifactResponse;

        public T Request { get; set; }

        public Saml2ArtifactResponse(Saml2Configuration config, T request) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Request = request;
        }

        public override XmlDocument ToXml()
        {
            throw new NotImplementedException();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2RequestException("Not a SAML2 Artifact Response.");
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            if (Status == Saml2StatusCodes.Success)
            {
                if (Request is Saml2AuthnResponse authnResponse)
                {
                    var authnReponse = GetAuthnReponse();
                    authnResponse.Read(authnReponse.OuterXml, Config.SignatureValidationCertificates != null && validate);
                }
                else
                {
                    throw new Saml2RequestException("Not a supported SAML2 request.");
                }

            }
        }

        private XmlNode GetAuthnReponse()
        {
            var assertionElements = XmlDocument.DocumentElement.SelectNodes(string.Format("//*[local-name()='{0}']", Saml2Constants.Message.AuthnResponse));
            if (assertionElements.Count != 1)
            {
                throw new Saml2RequestException("There is not exactly one Assertion element.");
            }
            return assertionElements[0];
        }
    }
}
