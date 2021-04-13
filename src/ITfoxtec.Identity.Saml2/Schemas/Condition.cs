using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas.Conditions;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// Implementation of Saml2:Condition
    /// </summary>
    public class Condition
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string elementName = Saml2Constants.Message.Conditions;

        public List<ConditionAbstract> Items { get; set; }

        public DateTimeOffset? NotOnOrAfter { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2Constants.AssertionNamespaceNameX, Saml2Constants.AssertionNamespaceX);
            if (NotOnOrAfter.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.NotOnOrAfter, NotOnOrAfter.Value.UtcDateTime.ToString(Schemas.Saml2Constants.DateTimeFormat, CultureInfo.InvariantCulture))
            }
            if (Items != null)
            {
                foreach (var condition in Items)
                {
                    yield return condition.ToXElement();
                }
            }
        }
    }
}