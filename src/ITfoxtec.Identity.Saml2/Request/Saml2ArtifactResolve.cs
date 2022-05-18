using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas;
using System;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Artifact Resolve.
    /// </summary>
    public class Saml2ArtifactResolve : Saml2Request
    {
        const string elementName = Saml2Constants.Message.ArtifactResolve;

        /// <summary>
        /// [Required]
        /// The artifact value that the requester received and now wishes to translate into the protocol message it
        /// represents. See [SAMLBind] for specific artifact format information.
        /// </summary>
        public string Artifact { get; set; }

        public Saml2ArtifactResolve(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.ArtifactResolutionService;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
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
    }
}
