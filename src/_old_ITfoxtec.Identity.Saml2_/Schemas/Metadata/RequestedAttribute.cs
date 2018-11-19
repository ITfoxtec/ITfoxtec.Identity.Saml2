using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    public class RequestedAttribute
    {
        const string elementName = Saml2MetadataConstants.Message.RequestedAttribute;
        const string nameFormat = Saml2MetadataConstants.AttributeNameFormat;

        public RequestedAttribute(string name, bool isRequired = true)
        {
            Name = name;
            IsRequired = isRequired;
        }

        public string Name { get; protected set; }

        public bool IsRequired { get; protected set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Name, Name);
            yield return new XAttribute(Saml2MetadataConstants.Message.NameFormat, nameFormat);
            yield return new XAttribute(Saml2MetadataConstants.Message.IsRequired, IsRequired);
        }
    }
}
