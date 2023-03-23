using System.Collections.Generic;
using System.Xml.Linq;
using System.Xml.Schema;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    public class SamlAttribute
    {
        const string elementName = Saml2MetadataConstants.Message.Attribute;

        public SamlAttribute(string name, string nameFormat = Saml2MetadataConstants.AttributeNameFormatUri, string friendlyName = null)
        {
            Name = name;
            NameFormat = nameFormat;
            FriendlyName = friendlyName;
        }

        public SamlAttribute(string name, IEnumerable<string> attributeValues, string nameFormat = Saml2MetadataConstants.AttributeNameFormatUri, string friendlyName = null)
            : this(name, nameFormat, friendlyName)
        {
            AttributeValues = attributeValues;
        }

        public string Name { get; protected set; }

        public string NameFormat { get; protected set; }

        public string FriendlyName { get; protected set; }

        public IEnumerable<string> AttributeValues { get; protected set; }

        public string AttributeValueType { get; set; } = "xs:string";

        public string AttributeValueDataTypeNamespace { get; set; } = XmlSchema.Namespace;

        public string AttributeValueTypeNamespace { get; set; } = XmlSchema.InstanceNamespace;

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.SamlAssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Name, Name);
            yield return new XAttribute(Saml2MetadataConstants.Message.NameFormat, NameFormat);
            if (!string.IsNullOrEmpty(FriendlyName))
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.FriendlyName, FriendlyName);
            }

            if (AttributeValues != null)
            {
                foreach (var attributeValue in AttributeValues)
                {
                    var attribVal = new XElement(Saml2MetadataConstants.SamlAssertionNamespaceX + Saml2MetadataConstants.Message.AttributeValue)
                    {
                        Value = attributeValue
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
