using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Util;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Cryptography;
using System.IdentityModel.Tokens;

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Generic Saml2 Response.
    /// </summary>
    public abstract class Saml2Response : Saml2Request
    {
        /// <summary>
        /// [Required]
        /// A code representing the status of the corresponding request.
        /// </summary>
        public Saml2StatusCodes Status { get; set; }

        /// <summary>
        /// [Optional]
        /// A reference to the identifier of the request to which the response corresponds, if any. If the response
        /// is not generated in response to a request, or if the ID attribute value of a request cannot be
        /// determined (for example, the request is malformed), then this attribute MUST NOT be present.
        /// Otherwise, it MUST
        /// </summary>
        public Saml2Id InResponseTo { get; set; }

        public Saml2Response(Saml2Configuration config) : base(config)
        { }

        protected override IEnumerable<XObject> GetXContent()
        {
            foreach (var item in  base.GetXContent())
            {
                yield return item;
            }

            yield return new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.Status, 
                new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.StatusCode, 
                    new XAttribute(Saml2Constants.Message.Value, Saml2StatusCodeUtil.ToString(Status))));

            if (InResponseTo != null)
            {
                yield return new XAttribute(Saml2Constants.Message.InResponseTo, InResponseTo);
            }
        }

        protected internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, validateXmlSignature);

            InResponseTo = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.InResponseTo].GetValueOrNull<Saml2Id>();

            Status = Saml2StatusCodeUtil.ToEnum(XmlDocument.DocumentElement[Saml2Constants.Message.Status, Saml2Constants.ProtocolNamespace.OriginalString][Saml2Constants.Message.StatusCode, Saml2Constants.ProtocolNamespace.OriginalString].Attributes[Saml2Constants.Message.Value].GetValueOrNull<string>());


        }      
    }
}
