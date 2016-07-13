using System;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// Elements of type EndpointType that describe endpoints that support the Single SignOn profiles defined in [SAMLProf].
    /// </summary>
    public class SingleSignOnService : EndpointType
    {
        const string elementName = Saml2MetadataConstants.Message.SingleSignOnService;

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

    }
}