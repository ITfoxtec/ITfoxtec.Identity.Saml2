using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// Describe indexed endpoints that support the profiles of the
    /// Authentication Request protocol defined in [SAMLProf]. All service providers support at least one
    /// such endpoint, by definition.
    /// </summary>
    public class AssertionConsumerService
    {
        const string elementName = Saml2MetadataConstants.Message.AssertionConsumerService;

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
        /// An optional boolean attribute used to designate the default endpoint among an indexed set.
        /// If set equal to false, the value is omitted and assumed to be false.
        /// </summary>
        public bool IsDefault { get; set; } = true;

        /// <summary>
        /// [Calculated]
        /// A required attribute that assigns a unique integer value to the endpoint so that it can be
        /// referenced in a protocol message.
        /// </summary>
        public int Index { get; internal set; }

        public XElement ToXElement(int index)
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent(index));

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent(int index)
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Binding, Binding.OriginalString);
            yield return new XAttribute(Saml2MetadataConstants.Message.Location, Location.OriginalString);
            yield return new XAttribute(Saml2MetadataConstants.Message.Index, index);
            if (IsDefault)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.IsDefault, IsDefault);
            }
        }
    }
}
