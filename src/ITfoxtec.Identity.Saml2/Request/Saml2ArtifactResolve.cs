using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Configuration;
using System.Linq;
using ITfoxtec.Identity.Saml2.Util;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Artifact Resolve.
    /// </summary>
    public class Saml2ArtifactResolve : Saml2Request
    {
        public override string ElementName => Saml2Constants.Message.ArtifactResolve;

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

            Destination = config.SingleSignOnDestination;  
        }

        /// <summary>
        /// Create SAML V2.0 defined artifact type with type code 0x0004.
        /// </summary>
        protected internal virtual void CreateArtifact()
        {
            var artifactBytes = new byte[44];
            artifactBytes[1] = 4; // 0x0004

            artifactBytes[2] = (byte)(Config.ArtifactResolutionService.Index >> 8);
            artifactBytes[3] = (byte)Config.ArtifactResolutionService.Index;

            if (string.IsNullOrEmpty(Issuer)) throw new ArgumentNullException("Issuer property");
            Array.Copy(Issuer.ComputeSha1Hash(), 0, artifactBytes, 4, 20);

            Array.Copy(RandomGenerator.GenerateArtifactMessageHandle(), 0, artifactBytes, 24, 20);

            Artifact = Convert.ToBase64String(artifactBytes);
        }

        /// <summary>
        /// Validate SAML V2.0 defined artifact type with type code 0x0004.
        /// </summary>
        protected internal virtual void ValidateArtifact()
        {
            if (Config.ValidateArtifact)
            {
                var artifactBytes = Convert.FromBase64String(Artifact);

                if (artifactBytes[1] != 4)
                {
                    throw new Saml2RequestException("Invalid Artifact type, not type code 0x0004. Artifact validation can be disabled in config.");
                }

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
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + ElementName);
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
            XmlDocument = XmlDocument.SignDocument(Config.SigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, CertificateIncludeOption, Id.Value, Config.IncludeKeyInfoName);
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            yield return new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.Artifact, Artifact);
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            Artifact = XmlDocument.DocumentElement[Saml2Constants.Message.Artifact, Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new Saml2RequestException("Not a SAML2 Artifact Resolve Request.");
            }
        }
    }
}
