using System;
using System.Collections.Generic;
using System.Linq;
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

        public Organization() { }

        public Organization(string name, string displayName, string url)
        {
            OrganizationNames = new[] { new LocalizedNameType(name) };
            OrganizationDisplayNames = new[] { new LocalizedNameType(displayName) }; ;
            OrganizationURLs = new[] { new LocalizedUriType(url) }; ;
        }

        public Organization(IEnumerable<LocalizedNameType> names, IEnumerable<LocalizedNameType> displayNames, IEnumerable<LocalizedUriType> urls)
        {
            OrganizationNames = names;
            OrganizationDisplayNames = displayNames;
            OrganizationURLs = urls;
        }

        /// <summary>
        /// [Required]
        /// Specifies the name of the organization responsible for the SAML entity or role.
        /// </summary>
        [Obsolete("The OrganizationName method is deprecated. Please use OrganizationNames which is a list of LocalizedNameType's.")]
        public string OrganizationName { get { return OrganizationNames?.Select(o => o.Name).FirstOrDefault(); } }

        /// <summary>
        /// [Required]
        /// Specifies the display name of the organization.
        /// </summary>
        [Obsolete("The OrganizationDisplayName method is deprecated. Please use OrganizationDisplayNames which is a list of LocalizedNameType's.")]
        public string OrganizationDisplayName { get { return OrganizationDisplayNames?.Select(o => o.Name).FirstOrDefault(); } }

        /// <summary>
        /// [Required]
        /// Specifies the URL of the organization.
        /// </summary>
        [Obsolete("The OrganizationURL method is deprecated. Please use OrganizationURLs which is a list of LocalizedUriType's.")]
        public string OrganizationURL { get { return OrganizationURLs?.Select(o => o.Uri).FirstOrDefault(); } }

        /// <summary>
        /// [Required]
        /// Specifies the name of the organization responsible for the SAML entity or role.
        /// </summary>
        public IEnumerable<LocalizedNameType> OrganizationNames { get; set; }

        /// <summary>
        /// [Required]
        /// Specifies the display name of the organization.
        /// </summary>
        public IEnumerable<LocalizedNameType> OrganizationDisplayNames { get; set; }

        /// <summary>
        /// [Required]
        /// Specifies the URL of the organization.
        /// </summary>
        public IEnumerable<LocalizedUriType> OrganizationURLs { get; set; }

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