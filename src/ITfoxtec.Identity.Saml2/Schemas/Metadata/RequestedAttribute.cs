﻿using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    public class RequestedAttribute
    {
        const string elementName = Saml2MetadataConstants.Message.RequestedAttribute;

        public RequestedAttribute(string name, bool isRequired = true, string nameFormat = Saml2MetadataConstants.AttributeNameFormat)
        {
            Name = name;
            IsRequired = isRequired;
            NameFormat = nameFormat;
        }

        public RequestedAttribute(string name, string attributeValue, bool isRequired = true, string nameFormat = Saml2MetadataConstants.AttributeNameFormat)
            : this(name, isRequired, nameFormat)
        {
            AttributeValue = attributeValue;
        }

        public string Name { get; protected set; }

        public bool IsRequired { get; protected set; }

        public string NameFormat { get; protected set; }

        public string AttributeValue { get; protected set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Name, Name);
            yield return new XAttribute(Saml2MetadataConstants.Message.NameFormat, NameFormat);
            yield return new XAttribute(Saml2MetadataConstants.Message.IsRequired, IsRequired);

            if (AttributeValue != null) {
                var attribVal = new XElement(Saml2MetadataConstants.SamlAssertionNamespaceX + Saml2MetadataConstants.Message.AttributeValue) {
                    Value = AttributeValue
                };
                attribVal.Add(new XAttribute(Saml2MetadataConstants.XmlSchemaInstanceNamespaceX + "type",
                    Saml2MetadataConstants.XmlSchemaNameSpaceAlias + ":string"));
                yield return attribVal;
            }
        }
    }
}
