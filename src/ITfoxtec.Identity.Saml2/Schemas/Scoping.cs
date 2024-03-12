using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas.Conditions;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// Implementation of Saml2:Scoping
    /// </summary>
    public class Scoping
    {
        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string elementName = Saml2Constants.Message.Scoping;

        public List<IDP> IDPList { get; set; }

        public string RequesterID { get; set; }


        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2Constants.AssertionNamespaceNameX, Saml2Constants.AssertionNamespaceX);

            if (RequesterID != null)
            {
                yield return new XAttribute(Saml2Constants.Message.RequesterID, RequesterID);
            }

            if (IDPList != null)
            {   
                foreach (var idp in IDPList)
                {
                    yield return idp.ToXElement();
                }
            }
        }
    }
}