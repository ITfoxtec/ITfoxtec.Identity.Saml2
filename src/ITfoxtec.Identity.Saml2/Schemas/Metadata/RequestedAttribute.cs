using System;
using System.Collections.Generic;
using System.Xml.Linq;
using System.Xml.Schema;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    public class RequestedAttribute
    {
        const string elementName = Saml2MetadataConstants.Message.RequestedAttribute;

        public RequestedAttribute(string name, bool isRequired = true, string nameFormat = Saml2MetadataConstants.AttributeNameFormat, string friendlyName = null)
        {
            Name = name;
            IsRequired = isRequired;
            NameFormat = nameFormat;
            FriendlyName = friendlyName;
        }

        public RequestedAttribute(string name, string attributeValue, bool isRequired = true, string nameFormat = Saml2MetadataConstants.AttributeNameFormat, string friendlyName = null)
            : this(name, isRequired, nameFormat, friendlyName)
        {
            AttributeValue = attributeValue;
        }

        public string Name { get; protected set; }

        public bool IsRequired { get; protected set; }

        public string NameFormat { get; protected set; }

        public string FriendlyName { get; protected set; }

        public string AttributeValue { get; protected set; }

        public string AttributeValueType { get; set; } = "xs:string";

        public string AttributeValueDataTypeNamespace { get; set; } = XmlSchema.Namespace;

        public string AttributeValueTypeNamespace { get; set; } = XmlSchema.InstanceNamespace;

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

            if (!string.IsNullOrEmpty(FriendlyName))
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.FriendlyName, FriendlyName);
            }

            if (AttributeValue != null) 
            {
                var attribVal = new XElement(Saml2MetadataConstants.SamlAssertionNamespaceX + Saml2MetadataConstants.Message.AttributeValue) 
                {
                    Value = AttributeValue
                };
                attribVal.Add(new XAttribute(Saml2MetadataConstants.SamlAssertionNamespaceNameX, Saml2MetadataConstants.SamlAssertionNamespace));
                if (!string.IsNullOrWhiteSpace(AttributeValueType) && TryGetAttributeValueTypeNamespaceName(out var attributeValueTypeNamespaceName) && !string.IsNullOrWhiteSpace(AttributeValueDataTypeNamespace) && !string.IsNullOrWhiteSpace(AttributeValueTypeNamespace))
                {
                    attribVal.Add(new XAttribute(XNamespace.Xmlns + attributeValueTypeNamespaceName, AttributeValueDataTypeNamespace));
                    attribVal.Add(new XAttribute(Saml2MetadataConstants.XsiInstanceNamespaceNameX, AttributeValueTypeNamespace));
                    attribVal.Add(new XAttribute(XNamespace.Get(AttributeValueTypeNamespace) + Saml2MetadataConstants.Message.Type, AttributeValueType));
                }
                yield return attribVal;
            }
        }

        private bool TryGetAttributeValueTypeNamespaceName(out string attributeValueTypeNamespaceName)
        {
            var splitValues = AttributeValueType?.Split(':');
            if (splitValues?.Length == 2)
            {
                attributeValueTypeNamespaceName = splitValues[0];
                return true;
            }

            attributeValueTypeNamespaceName = null;
            return false;
        }
    }
}
