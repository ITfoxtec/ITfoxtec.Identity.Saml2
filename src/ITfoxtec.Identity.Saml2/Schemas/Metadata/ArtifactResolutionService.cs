using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// Elements of type EndpointType that describe endpoints that support the Single Logout profiles defined in [SAMLProf].
    /// </summary>
    public class ArtifactResolutionService : IndexedEndpointType
    {
        const string elementName = Saml2MetadataConstants.Message.ArtifactResolutionService;

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }
    }
}
