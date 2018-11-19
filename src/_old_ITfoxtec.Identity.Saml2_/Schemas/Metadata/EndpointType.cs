using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The complex type EndpointType describes a SAML protocol binding endpoint at which a SAML entity can be sent 
    /// protocol messages.
    /// </summary>
    public abstract class EndpointType
    {
        /// <summary>
        /// [Required]
        /// A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
        /// assigned a URI to identify it.
        /// </summary>
        public Uri Binding { get; set; }

        /// <summary>
        /// [Required]
        /// A required URI attribute that specifies the location of the endpoint. The allowable syntax of this
        /// URI depends on the protocol binding.
        /// </summary>
        public Uri Location { get; set; }

        /// <summary>
        /// [Optional]
        /// Optionally specifies a different location to which response messages sent as part of the protocol
        /// or profile should be sent. The allowable syntax of this URI depends on the protocol binding.
        /// </summary>
        public Uri ResponseLocation { get; set; }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Binding != null)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.Binding, Binding.OriginalString);
            }
            if (Location != null)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.Location, Location.OriginalString);
            }
            if(ResponseLocation != null)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.ResponseLocation, ResponseLocation.OriginalString);
            }            
        }

        protected internal EndpointType Read(XmlElement xmlElement)
        {
            Binding = xmlElement.Attributes[Saml2MetadataConstants.Message.Binding].GetValueOrNull<Uri>();
            Location = xmlElement.Attributes[Saml2MetadataConstants.Message.Location].GetValueOrNull<Uri>();
            ResponseLocation = xmlElement.Attributes[Saml2MetadataConstants.Message.ResponseLocation].GetValueOrNull<Uri>();            

            return this;
        }
    }
}
