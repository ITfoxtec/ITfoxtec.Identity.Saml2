using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The IDPEntry element specifies a single identity provider trusted by the requester to authenticate the
    /// presenter.Its IDPEntryType complex type defines the following attributes:
    /// </summary>
    public class IDPEntry
    {
        public const string elementName = Saml2Constants.Message.IDPEntry;

        /// <summary>
        /// [Required]
        /// The unique identifier of the identity provider.See Section 8.3.6 for a description of such identifiers.
        /// </summary>
        public string ProviderID { get; set; }

        /// <summary>
        /// [Optional]
        /// A human-readable name for the identity provider.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// [Optional]
        /// A URI reference representing the location of a profile-specific endpoint supporting the authentication
        /// request protocol.The binding to be used must be understood from the profile of use.
        /// </summary>
        public string Loc { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

         protected virtual IEnumerable<XObject> GetXContent()
         {
            if (ProviderID != null)
            {
                yield return new XAttribute(Saml2Constants.Message.ProviderID, ProviderID);
            }

            if (Name != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Name, Name);
            }

            if (Loc != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Loc, Loc);
            }
        }
    }
}