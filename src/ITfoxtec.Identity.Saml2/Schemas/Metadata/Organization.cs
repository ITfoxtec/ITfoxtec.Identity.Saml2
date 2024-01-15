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

        public Organization(string name, string displayName, string url)
        {
            OrganizationName = name;
            OrganizationDisplayName = displayName;
            OrganizationURL = url;
        }

        /// <summary>
        /// [Required]
        /// Specifies the name of the organization responsible for the SAML entity or role.
        /// </summary>
        public string OrganizationName { get; protected set; }

        /// <summary>
        /// [Required]
        /// OrganizationDisplayName is an optional string element that specifies the display name of the organization.
        /// </summary>
        public string OrganizationDisplayName { get; protected set; }

        /// <summary>
        /// [Required]
        /// OrganizationURL is an optional anyURI element that specifies the URL of the organization.
        /// </summary>
        public string OrganizationURL { get; protected set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (OrganizationName != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.OrganizationName, OrganizationName);
            }

            if (OrganizationDisplayName != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.OrganizationDisplayName, OrganizationDisplayName);
            }

            if (OrganizationURL != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.OrganizationURL, OrganizationURL);
            }
        }
    }
}