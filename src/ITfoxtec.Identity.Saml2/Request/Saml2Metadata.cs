using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Metadata.
    /// </summary>
    public class Saml2Metadata
    {
        /// <param name="entitiesDescriptor">[Required] The EntitiesDescriptor element contains the metadata for an optionally named group of SAML entities.</param>
        public Saml2Metadata(params EntityDescriptor[] entitiesDescriptor)
        {
            EntitiesDescriptor = entitiesDescriptor;
        }

        /// <param name="entitiesDescriptor">[Required] The EntitiesDescriptor element contains the metadata for an optionally named group of SAML entities.</param>
        public Saml2Metadata(Saml2Configuration config, params EntityDescriptor[] entitiesDescriptor)
        {
            EntitiesDescriptor = entitiesDescriptor;
            MetadataSigningCertificate = config.SigningCertificate;
            SignatureAlgorithm = config.SignatureAlgorithm;
            XmlCanonicalizationMethod = config.XmlCanonicalizationMethod;
        }

        /// <summary>
        /// [Optional]
        /// The EntitiesDescriptor element contains the metadata for a group of SAML entities.
        /// </summary>
        public IEnumerable<EntityDescriptor> EntitiesDescriptor { get; set; }

        /// <summary>
        /// [Required]
        /// The EntityDescriptor element contains the metadata for a single SAML entity.
        /// </summary>
        [Obsolete("The " + nameof(EntityDescriptor) + " is deprecated. Please use " + nameof(EntitiesDescriptor) + " which is a list of entity descriptors.")]
        public EntityDescriptor EntityDescriptor { get => EntitiesDescriptor.FirstOrDefault(); set => EntitiesDescriptor = new[] { value }; }

        /// <summary>
        /// [Optional]
        /// An metadata XML signature that authenticates the containing element and its contents.
        /// </summary>
        public X509Certificate2 MetadataSigningCertificate { get; set; }

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; } = X509IncludeOption.EndCertOnly;

        /// <summary>
        /// [Optional]
        /// Optional attribute indicates the expiration time of the metadata and any contained elements.
        /// 
        /// Metadata is valid until in days from now.
        /// </summary>
        public int? ValidUntil { get; set; }

        /// <summary>
        /// Signature algorithm to use when signing.
        /// </summary>
        public string SignatureAlgorithm { get; set; } = Saml2SecurityAlgorithms.RsaSha256Signature;

        /// <summary>
        /// XML Canonicalization method to use when signing.
        /// </summary>
        public string XmlCanonicalizationMethod { get; set; } = SignedXml.XmlDsigExcC14NTransformUrl;

        /// <summary>
        /// A document-unique identifier for the element, typically used as a reference point when signing.
        /// </summary>
        public Saml2Id Id { get; protected set; } = new Saml2Id();

        /// <summary>
        /// The ID as string.
        /// </summary>
        /// <value>The ID string.</value>
        public string IdAsString
        {
            get { return Id.Value; }
        }

        /// <summary>
        /// Saml2 metadata Xml Document.
        /// </summary>
        public XmlDocument XmlDocument { get; protected set; }

        /// <summary>
        /// To metadata Xml.
        /// </summary>
        public string ToXml()
        {
            return XmlDocument != null ? XmlDocument.OuterXml : null;
        }

        /// <summary>
        /// Creates Saml2 metadata Xml Document.
        /// </summary>
        public Saml2Metadata CreateMetadata()
        {
            var xmlDocument = ToXElement().ToXmlDocument();
            if (MetadataSigningCertificate != null)
            {
                xmlDocument.SignDocument(MetadataSigningCertificate, SignatureAlgorithm, XmlCanonicalizationMethod, CertificateIncludeOption, IdAsString);
            }
            XmlDocument = xmlDocument;
            return this;
        }

        protected XElement ToXElement()
        {
            if (EntitiesDescriptor.Count() == 1)
            {
                var singleDescriptorMetadata = EntityDescriptor.ToXElement();
                //‌ Copy Id for signing
                Id = EntityDescriptor.Id;
                singleDescriptorMetadata.SetAttributeValue(Saml2MetadataConstants.MetadataNamespaceNameX, Saml2MetadataConstants.MetadataNamespace);
                if (ValidUntil.HasValue)
                {
                    singleDescriptorMetadata.SetAttributeValue(Saml2MetadataConstants.Message.ValidUntil, DateTimeOffset.UtcNow.AddDays(ValidUntil.Value).UtcDateTime.ToString(Schemas.Saml2Constants.DateTimeFormat, CultureInfo.InvariantCulture));
                }
                return singleDescriptorMetadata;
            }
            var multiDescriptorMetadata = new XElement(Saml2MetadataConstants.MetadataNamespaceX + nameof(EntitiesDescriptor));
            multiDescriptorMetadata.Add(GetXContent());
            return multiDescriptorMetadata;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.MetadataNamespaceNameX, Saml2MetadataConstants.MetadataNamespace);
            yield return new XAttribute(Saml2MetadataConstants.Message.Id, IdAsString);
            if (ValidUntil.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.ValidUntil, DateTimeOffset.UtcNow.AddDays(ValidUntil.Value).UtcDateTime.ToString(Schemas.Saml2Constants.DateTimeFormat, CultureInfo.InvariantCulture));
            }
            foreach (var entityDescriptor in EntitiesDescriptor)
            {
                yield return entityDescriptor.ToXElement();
            }
        }
    }
}
