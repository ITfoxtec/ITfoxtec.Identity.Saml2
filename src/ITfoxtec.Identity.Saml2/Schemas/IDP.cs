using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas.Conditions;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// Implementation of Saml2:IDPListType
    /// </summary>
    public class IDP
    {
        public const string elementName = Saml2Constants.Message.IDP;

        public IDPEntry IDPEntry { get; set; }

        public string GetComplete { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.AssertionNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

         protected virtual IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2Constants.AssertionNamespaceNameX, Saml2Constants.AssertionNamespaceX);

            if (GetComplete != null)
            {
                yield return new XAttribute(Saml2Constants.Message.GetComplete, GetComplete);
            }

            if (IDPEntry != null)
            {   
                yield return IDPEntry.ToXElement();
            }
        }
    }
}