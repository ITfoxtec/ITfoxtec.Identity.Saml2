﻿using System;
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
        [Obsolete("The ServiceName method is deprecated. Please use ServiceNames which is a list of service names.")]
        public LocalizedNameType ServiceName { get; set; }

        /// <summary>
        /// [Required]
        /// A unique numeric index of the service.
        /// </summary>
        public int Index { get; set; } = 0;

        /// <summary>
        /// [Required]
        /// Language-qualified names for the service.
        /// </summary>
        public IEnumerable<LocalizedNameType> ServiceNames { get; set; }

        /// <summary>
        /// [Required]
        /// A required element specifying attributes required or desired by this service.
        /// </summary>
        public IEnumerable<RequestedAttribute> RequestedAttributes { get; set; }

        /// <summary>
        /// [Optional]
        /// Identifies if this service is the default service.
        /// </summary>
        public bool IsDefault { get; set; } = true;

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Index, Index);
            if (IsDefault)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.IsDefault, true);
            }

            if (ServiceNames != null)
            {
                foreach (var serviceName in ServiceNames)
                {
                    yield return serviceName.ToXElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.ServiceName);
                }
            }
            else if (ServiceName != null)
            {
                yield return ServiceName.ToXElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.ServiceName);
            }

            if (RequestedAttributes != null)
            {
                foreach (var reqAtt in RequestedAttributes)
                {
                    yield return reqAtt.ToXElement();
                } 
            }
        }
    }
}
