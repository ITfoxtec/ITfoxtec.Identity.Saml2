using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Conditions
{
    public class OneTimeUse : ICondition
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        const string elementName = Saml2Constants.Message.OneTimeUse;

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            return envelope;
        }
    }
}