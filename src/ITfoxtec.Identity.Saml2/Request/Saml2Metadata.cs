﻿using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Metadata.
    /// </summary>
    public class Saml2Metadata
    {
        /// <param name="entityDescriptor">The entityDescriptor element contains the metadata.</param>
        public Saml2Metadata(EntityDescriptor entityDescriptor)
        {
            EntitiesDescriptor = entitiesDescriptor;
        }

        /// <param name="entitiesDescriptor">The entitiesDescriptor element contains the metadata for an optionally named group of SAML entities.</param>
        public Saml2Metadata(EntitiesDescriptor entitiesDescriptor)
        {
            EntitiesDescriptor = entitiesDescriptor;
        }
        /// <summary>
        /// Either the EntityDescriptor or EntitiesDescriptor is required.
        /// EntityDescriptor contains the metadata.
        /// </summary>
        public EntityDescriptor EntityDescriptor { get; protected set; }

        /// <summary>
        /// Either the EntityDescriptor or EntitiesDescriptor is required.
        /// EntitiesDescriptor contains the metadata for an optionally named group of SAML entities.
        /// </summary>
        public EntitiesDescriptor EntitiesDescriptor { get; protected set; }
        
        /// <summary>
        /// Saml2 metadata Xml Document.
        /// </summary>
        public XmlDocument XmlDocument { get; protected set; }

        /// <summary>
        /// To metadata Xml.
        /// </summary>
        public string ToXml()
        {
            return XmlDocument != null ? XmlDocument.OuterXml : null;
        }

        /// <summary>
        /// Creates Saml2 metadata Xml Document.
        /// </summary>
        public Saml2Metadata CreateMetadata()
        {
            if (EntityDescriptor != null)
            {
                XmlDocument = EntityDescriptor.ToXmlDocument();
            }
            else
            {
                XmlDocument = EntitiesDescriptor.ToXmlDocument();
            }
            return this;
        }
    }
}
