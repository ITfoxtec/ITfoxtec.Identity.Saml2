using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System.Xml;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Metadata.
    /// </summary>
    public class Saml2Metadata
    {
        /// <param name="entityDescriptor">[Required] The EntitiesDescriptor element contains the metadata for an optionally named group of SAML entities.</param>
        public Saml2Metadata(EntityDescriptor entityDescriptor)
        {
            EntityDescriptor = entityDescriptor;
        }

        /// <summary>
        /// [Required]
        /// The EntitiesDescriptor element contains the metadata for an optionally named group of SAML entities.
        /// </summary>
        public EntityDescriptor EntityDescriptor { get; protected set; }

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
            XmlDocument = EntityDescriptor.ToXmlDocument();
            return this;
        }
    }
}
