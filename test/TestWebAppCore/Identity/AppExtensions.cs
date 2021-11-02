using Schemas = ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace TestWebAppCore.Identity
{
    public class AppExtensions : Schemas.Extensions
    {
        static readonly XName eidasNamespaceNameX = XNamespace.Xmlns + "eidas";
        static readonly Uri eidasNamespace = new Uri("http://eidas.europa.eu/saml-extensions");
        static readonly XNamespace eidasNamespaceX = XNamespace.Get(eidasNamespace.OriginalString);

        public AppExtensions()
        {
            Element.Add(GetXContent());
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(eidasNamespaceNameX, eidasNamespace.OriginalString);

            yield return new XElement(eidasNamespaceX + "SPType", "public");

            yield return new XElement(eidasNamespaceX + "RequestedAttributes",
                GetRequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"),
                GetRequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"),
                GetRequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"),
                GetRequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentAddress"),
                GetRequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"),
                GetRequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth"),
                GetRequestedAttribute("http://www.stork.gov.eu/1.0/countryCodeOfBirth"),
                GetRequestedAttribute("http://www.stork.gov.eu/1.0/eMail"),
                GetRequestedAttribute("http://www.stork.gov.eu/1.0/age"),
                GetRequestedAttribute("http://www.stork.gov.eu/1.0/isAgeOver", value: "18"),
                GetRequestedAttribute("http://schemas.eidentity.cz/moris/2016/identity/claims/phonenumber"),
                GetRequestedAttribute("http://schemas.eidentity.cz/moris/2016/identity/claims/tradresaid"),
                GetRequestedAttribute("http://schemas.eidentity.cz/moris/2016/identity/claims/idtype"),
                GetRequestedAttribute("http://schemas.eidentity.cz/moris/2016/identity/claims/idnumber"));
        }

        private static XElement GetRequestedAttribute(string name, bool isRequired = false, string value = null)
        {
            var element = new XElement(eidasNamespaceX + "RequestedAttribute",
                                 new XAttribute("Name", name),
                                 new XAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"),
                                 new XAttribute("isRequired", isRequired));

            if (!string.IsNullOrWhiteSpace(value))
            {
                element.Add(new XElement(eidasNamespaceX + "AttributeValue", value));
            }
            return element;
        }
    }
}
