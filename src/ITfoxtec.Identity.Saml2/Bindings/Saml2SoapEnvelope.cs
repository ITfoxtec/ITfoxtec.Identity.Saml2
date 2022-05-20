using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2SoapEnvelope<T> where T : Saml2Request
    {
        public Saml2SoapEnvelope(Saml2ArtifactResolve<T> saml2ArtifactResolve)
        {
            RequestBody = saml2ArtifactResolve.ToXml();
        }

        private XmlDocument RequestBody { get; set; }

        public XmlDocument ResponseBody { get; private set; }

        public XmlDocument ToSoapXml()
        {
            var envelope = new XElement(Saml2Constants.SoapEnvironmentNamespaceX + Saml2Constants.Message.Envelope);

            envelope.Add(GetXContent());

            XmlDocument xmldoc = envelope.ToXmlDocument();
            return xmldoc;
        }

        public void FromSoapXml(string xml)
        {
            var xmlDoc = xml.ToXmlDocument();

            var bodyList = GetNodesByLocalname(xmlDoc.DocumentElement, "Body");
            if (bodyList.Count != 1)
            {
                throw new Exception("There is not exactly one Body element.");
            }

            var faultBody = GetNodeByLocalname(bodyList[0], "Fault");
            if (faultBody != null)
            {
                var faultcode = GetNodeByLocalname(faultBody, "faultcode");
                var faultstring = GetNodeByLocalname(faultBody, "faultstring");
                throw new Saml2RequestException("Soap Error: " + faultcode + "\n" + faultstring);
            }

            ResponseBody = bodyList[0].InnerXml.ToXmlDocument();
        }


        private XmlNodeList GetNodesByLocalname(XmlNode xe, string localName)
        {
            return xe.SelectNodes(string.Format("//*[local-name()='{0}']", localName));
        }

        private XmlNode GetNodeByLocalname(XmlNode xe, string localName)
        {
            return xe.SelectSingleNode(string.Format("//*[local-name()='{0}']", localName));
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2Constants.SoapEnvironmentNamespaceNameX, Saml2Constants.SoapEnvironmentNamespace.OriginalString);
            yield return new XElement(Saml2Constants.SoapEnvironmentNamespaceX + Saml2Constants.Message.Body, RequestBody.ToXDocument().Root);
        }
    }
}