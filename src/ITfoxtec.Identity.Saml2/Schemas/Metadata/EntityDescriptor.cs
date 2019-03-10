using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The EntitiesDescriptor element contains the metadata for an optionally named group of SAML entities.
    /// </summary>
    public class EntityDescriptor
    {
        const string elementName = Saml2MetadataConstants.Message.EntityDescriptor;

        public Saml2Configuration Config { get; protected set; }

        /// <summary>
        /// Specifies the unique identifier of the SAML entity whose metadata is described by the element's contents.
        /// </summary>
        public string EntityId { get; protected set; }

        /// <summary>
        /// A document-unique identifier for the element, typically used as a reference point when signing.
        /// </summary>
        public Saml2Id Id { get; protected set; }

        /// <summary>
        /// The ID as string.
        /// </summary>
        /// <value>The ID string.</value>
        public string IdAsString
        {
            get { return Id.Value; }
        }

        /// <summary>
        /// [Optional]
        /// An metadata XML signature that authenticates the containing element and its contents.
        /// </summary>
        public X509Certificate2 MetadataSigningCertificate { get; protected set; }

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional attribute indicates the expiration time of the metadata contained in the element and any contained elements.
        /// 
        /// Metadata is valid until in days from now.
        /// </summary>
        public int? ValidUntil { get; set; }

        /// <summary>
        /// [Optional]
        /// The SPSSODescriptor element extends SSODescriptorType with content reflecting profiles specific
        /// to service providers. 
        /// </summary>
        public SPSsoDescriptor SPSsoDescriptor  { get; set; }

        /// <summary>
        /// [Optional]
        /// The IDPSSODescriptor element extends SSODescriptorType with content reflecting profiles specific 
        /// to identity providers supporting SSO.
        /// </summary>
        public IdPSsoDescriptor IdPSsoDescriptor { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional element identifying various kinds of contact personnel.
        /// </summary>
        public ContactPerson ContactPerson { get; set; }

        public EntityDescriptor()
        { }

        public EntityDescriptor(Saml2Configuration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Config = config;
            EntityId = config.Issuer;
            Id = new Saml2Id();
            MetadataSigningCertificate = config.SigningCertificate;
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        public XmlDocument ToXmlDocument()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());
            var xmlDocument = envelope.ToXmlDocument();
            if(MetadataSigningCertificate != null)
            {
                xmlDocument.SignDocument(MetadataSigningCertificate, Config.SignatureAlgorithm, CertificateIncludeOption, IdAsString);
            }
            return xmlDocument;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (EntityId == null)
            {
                throw new ArgumentNullException("EntityId property");
            }
            yield return new XAttribute(Saml2MetadataConstants.Message.EntityId, EntityId);
            yield return new XAttribute(Saml2MetadataConstants.Message.Id, IdAsString);
            if (ValidUntil.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.ValidUntil, DateTimeOffset.UtcNow.AddDays(ValidUntil.Value).UtcDateTime.ToString("o", CultureInfo.InvariantCulture));
            }
            yield return new XAttribute(Saml2MetadataConstants.MetadataNamespaceNameX, Saml2MetadataConstants.MetadataNamespace);

            if (SPSsoDescriptor != null)
            {
                yield return SPSsoDescriptor.ToXElement();
            }

            if (IdPSsoDescriptor != null)
            {
                yield return IdPSsoDescriptor.ToXElement();
            }

            if (ContactPerson != null)
            {
                yield return ContactPerson.ToXElement();
            }
        }

        public virtual EntityDescriptor ReadIdPSsoDescriptor(string idPMetadataXml)
        {
            var metadataXmlDocument = idPMetadataXml.ToXmlDocument();

            if (metadataXmlDocument.DocumentElement.NamespaceURI != Saml2MetadataConstants.MetadataNamespace.OriginalString)
            {
                throw new Saml2RequestException("Not Metadata.");
            }

            EntityId = metadataXmlDocument.DocumentElement.Attributes[Saml2MetadataConstants.Message.EntityId].GetValueOrNull<string>();

            Id = metadataXmlDocument.DocumentElement.Attributes[Saml2MetadataConstants.Message.Id].GetValueOrNull<Saml2Id>();

            var idPSsoDescriptorElement = metadataXmlDocument.DocumentElement[Saml2MetadataConstants.Message.IdPSsoDescriptor, Saml2MetadataConstants.MetadataNamespace.OriginalString];
            if (idPSsoDescriptorElement != null)
            {
                IdPSsoDescriptor = new IdPSsoDescriptor().Read(idPSsoDescriptorElement);
            }

            return this;
        }

        public virtual EntityDescriptor ReadIdPSsoDescriptorFromFile(string idPMetadataFile)
        {
            return ReadIdPSsoDescriptor(File.ReadAllText(idPMetadataFile));
        }

        public virtual EntityDescriptor ReadIdPSsoDescriptorFromUrl(Uri idPMetadataUrl)
        {
            using (var webClient = new WebClient())
            {
                return ReadIdPSsoDescriptor(webClient.DownloadString(idPMetadataUrl));
            }
        }
    }
}
