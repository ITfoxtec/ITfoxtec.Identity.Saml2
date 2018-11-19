using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The ContactPerson element specifies basic contact information about a person responsible in some
    /// capacity for a SAML entity or role. The use of this element is always optional. Its content is informative in
    /// nature and does not directly map to any core SAML elements or attributes.
    /// </summary>
    public class ContactPerson
    {
        const string elementName = Saml2MetadataConstants.Message.ContactPerson;

        public ContactPerson(string contactType)
        {
            ContactType = contactType;
        }

        /// <summary>
        /// [Required]
        /// Specifies the type of contact using the ContactTypeType enumeration. The possible values are
        /// technical, support, administrative, billing, and other.
        /// </summary>
        public string ContactType { get; protected set; }

        /// <summary>
        /// [Optional]
        /// Optional string element that specifies the name of the company for the contact person.
        /// </summary>
        public string Company { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional string element that specifies the given (first) name of the contact person.
        /// </summary>
        public string GivenName { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional string element that specifies the surname of the contact person.
        /// </summary>
        public string SurName { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional string element containing mailto: URIs representing e-mail addresses belonging to the
        /// contact person.
        /// </summary>
        public string EmailAddress { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional string element specifying a telephone number of the contact person.
        /// </summary>
        public string TelephoneNumber { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.ContactType, ContactType);

            if (Company != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.Company, Company);
            }

            if (GivenName != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.GivenName, GivenName);
            }

            if (SurName != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.SurName, SurName);
            }

            if (EmailAddress != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.EmailAddress, EmailAddress);
            }

            if (TelephoneNumber != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.TelephoneNumber, TelephoneNumber);
            }
        }
    }
}
