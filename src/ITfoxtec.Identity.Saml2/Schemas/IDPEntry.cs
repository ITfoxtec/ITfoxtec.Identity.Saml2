using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas.Conditions;

namespace ITfoxtec.Identity.Saml2.Schemas
{    
    /// <summary>
    /// Implementation of Saml2:IDEntry
    /// </summary>
    public class IDPEntry
    {
        public const string elementName = Saml2Constants.Message.IDPEntry;

        public string ProviderID { get; set; }

        public string Name { get; set; }

        public string Loc { get; set; }

        public string Binding { get; set; }

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

            if (ProviderID != null)
            {
                yield return new XAttribute(Saml2Constants.Message.ProviderID, ProviderID);
            }

            if (Name != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Name, Name);
            }

            if (Loc != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Loc, Loc);
            }

            if (Binding != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Binding, Binding);
            }

            if (GetComplete != null)
            {
                yield return new XAttribute(Saml2Constants.Message.GetComplete, GetComplete);
            }
        }

    }
}