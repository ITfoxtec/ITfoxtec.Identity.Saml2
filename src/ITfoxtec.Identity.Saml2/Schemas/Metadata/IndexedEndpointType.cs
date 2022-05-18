using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The complex type IndexedEndpointType extends EndpointType with a pair of attributes to permit the
    /// indexing of otherwise identical endpoints so that they can be referenced by protocol messages.
    /// </summary>
    public abstract class IndexedEndpointType : EndpointType
    {
        /// <summary>
        /// [Required]
        /// A required attribute that assigns a unique integer value to the endpoint so that it can be
        /// referenced in a protocol message.The index value need only be unique within a collection of like
        /// elements contained within the same parent element (i.e., they need not be unique across the
        /// entire instance).
        /// </summary>
        public int Index { get; set; }

        /// <summary>
        /// [Optional]
        /// An optional boolean attribute used to designate the default endpoint among an indexed set. If
        /// omitted, the value is assumed to be false.
        /// </summary>
        public bool? IsDefault { get; set; }

        protected override IEnumerable<XObject> GetXContent()
        {
            base.GetXContent();

            yield return new XAttribute(Saml2MetadataConstants.Message.Index, Index);

            if (IsDefault.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.IsDefault, IsDefault);
            }
        }

        protected override internal EndpointType Read(XmlElement xmlElement)
        {
            base.Read(xmlElement);

            Index = xmlElement.Attributes[Saml2MetadataConstants.Message.Index].GetValueOrNull<int>();
            IsDefault = xmlElement.Attributes[Saml2MetadataConstants.Message.IsDefault].GetValueOrNull<bool?>();

            return this;
        }
    }
}
