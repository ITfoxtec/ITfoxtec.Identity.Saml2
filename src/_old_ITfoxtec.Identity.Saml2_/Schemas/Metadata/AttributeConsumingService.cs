using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The AttributeConsumingService element defines a particular service offered by the service
    /// provider in terms of the attributes the service requires or desires.
    /// </summary>
    public class AttributeConsumingService
    {
        const string elementName = Saml2MetadataConstants.Message.AttributeConsumingService;

        /// <summary>
        /// [Required]
        /// Language-qualified names for the service.
        /// </summary>
        public ServiceName ServiceName { get; set; }

        /// <summary>
        /// [Required]
        /// A required element specifying attributes required or desired by this service.
        /// </summary>
        public IEnumerable<RequestedAttribute> RequestedAttributes { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Index, 0);
            yield return new XAttribute(Saml2MetadataConstants.Message.IsDefault, true);

            yield return ServiceName.ToXElement();

            foreach (var reqAtt in RequestedAttributes)
            {
                yield return reqAtt.ToXElement();
            }
        }
    }
}
