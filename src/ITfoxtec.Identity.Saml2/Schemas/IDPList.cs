using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The element specifies the identity providers trusted by the requester to authenticate the presenter.
    /// </summary>
    public class IDPList
    {
        public const string elementName = Saml2Constants.Message.IDPList;

        /// <summary>
        /// [One or More]
        /// Information about a single identity provider.
        /// </summary>
        public IEnumerable<IDPEntry> IDPEntry { get; set; }

        /// <summary>
        /// [Optional]
        /// If the IDPList is not complete, using this element specifies a URI reference that can be used to       
        /// retrieve the complete list.
        /// </summary>
        public string GetComplete { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

         protected virtual IEnumerable<XObject> GetXContent()
         {
            if (GetComplete != null)
            {
                yield return new XElement(Saml2Constants.Message.GetComplete, GetComplete);
            }

            if (IDPEntry != null)
            {   
                foreach (var entry in IDPEntry)
                {
                    yield return entry.ToXElement();
                }
            }
        }
    }
}