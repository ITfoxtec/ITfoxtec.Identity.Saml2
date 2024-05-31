using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The Organization element specifies basic contact information about the company or organization that is publishing the metadata document.
    /// The use of this element is always optional. Its content is informative in
    /// nature and does not directly map to any core SAML elements or attributes.
    /// </summary>
    public class Organization
    {
        const string elementName = Saml2MetadataConstants.Message.Organization;

        /// <summary>
        /// [Required]
        /// Specifies the name of the organization responsible for the SAML entity or role.
        /// </summary>
        public IEnumerable<LocalizedName> OrganizationNames { get; set; }

        /// <summary>
        /// [Required]
        /// Specifies the display name of the organization.
        /// </summary>
        public IEnumerable<LocalizedName> OrganizationDisplayNames { get; set; }

        /// <summary>
        /// [Required]
        /// Specifies the URL of the organization.
        /// </summary>
        public IEnumerable<LocalizedUri> OrganizationURLs { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (OrganizationNames != null)
            {
                foreach (var name in OrganizationNames)
                {
                    yield return name.ToXElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.OrganizationName);
                }
            }

            if (OrganizationDisplayNames != null)
            {
                foreach (var displayName in OrganizationDisplayNames)
                {
                    yield return displayName.ToXElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.OrganizationDisplayName);
                }
            }

            if (OrganizationURLs != null)
            {
                foreach (var url in OrganizationURLs)
                {
                    yield return url.ToXElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.OrganizationURL);
                }
            }
        }
    }
}