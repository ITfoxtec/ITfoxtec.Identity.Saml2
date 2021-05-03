using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Conditions
{
    public class ProxyRestriction : ICondition
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        const string elementName = Saml2Constants.Message.ProxyRestriction;

        public List<Audience> Audiences { get; set; }

        public uint? Count { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Audiences != null)
            {
                foreach (var audience in Audiences)
                {
                    yield return audience.ToXElement();
                }
            }

            if (Count.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.Count, Count.Value);
            }
        }
    }
}