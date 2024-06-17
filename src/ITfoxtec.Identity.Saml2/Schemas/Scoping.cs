using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The element specifies the identity providers trusted by the requester to authenticate the
    /// presenter, as well as limitations and context related to proxying of the AuthnRequest message to
    /// subsequent identity providers by the responder. 
    /// </summary>
    public class Scoping
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string elementName = Saml2Constants.Message.Scoping;

        /// <summary>
        /// [Optional]
        /// An advisory list of identity providers and associated information that the requester deems acceptable
        /// to respond to the request.
        /// </summary>
        public IDPList IDPList { get; set; }

        /// <summary>
        /// [Zero or More]
        /// Identifies the set of requesting entities on whose behalf the requester is acting. Used to communicate
        /// the chain of requesters when proxying occurs.
        /// </summary>
        public IEnumerable<string> RequesterID { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            if (RequesterID != null)
            {
                foreach (var item in RequesterID)
                {
                    yield return new XElement(Saml2Constants.Message.RequesterID, item);
                }
            }

            if (IDPList != null)
            {   
                yield return IDPList.ToXElement();
            }
        }
    }
}