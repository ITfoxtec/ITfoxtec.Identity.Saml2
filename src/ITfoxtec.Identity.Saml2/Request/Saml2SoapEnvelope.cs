using ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2SoapEnvelope<T> : Saml2Request where T : Saml2Request
    {
        const string elementName = Saml2Constants.Message.Envelope;

        public Saml2SoapEnvelope(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
        }


        //public Saml2SoapEnvelope(Saml2ArtifactResolve<T> saml2ArtifactResolve)
        //{
        //    RequestBody = saml2ArtifactResolve.ToXml();
        //}

        private XmlDocument RequestBody { get; set; }

        public XmlDocument ResponseBody { get; private set; }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.SoapEnvironmentNamespaceX + elementName);

            envelope.Add(GetXContent());

            XmlDocument xmldoc = envelope.ToXmlDocument();
            return xmldoc;
        }
        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2Constants.SoapEnvironmentNamespaceNameX, Saml2Constants.SoapEnvironmentNamespace.OriginalString);
            yield return new XElement(Saml2Constants.SoapEnvironmentNamespaceX + Saml2Constants.Message.Body, RequestBody.ToXDocument().Root);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2RequestException("Not a SAML2 SOAP Request.");
            }
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            ForceAuthn = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.ForceAuthn].GetValueOrNull<bool>();

            IsPassive = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.IsPassive].GetValueOrNull<bool>();

            AssertionConsumerServiceUrl = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.AssertionConsumerServiceURL].GetValueOrNull<Uri>();

            ProtocolBinding = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.ProtocolBinding].GetValueOrNull<Uri>();

            Subject = XmlDocument.DocumentElement[Saml2Constants.Message.Subject, Saml2Constants.AssertionNamespace.OriginalString].GetElementOrNull<Subject>();

            NameIdPolicy = XmlDocument.DocumentElement[Saml2Constants.Message.NameIdPolicy, Saml2Constants.ProtocolNamespace.OriginalString].GetElementOrNull<NameIdPolicy>();

            RequestedAuthnContext = XmlDocument.DocumentElement[Saml2Constants.Message.RequestedAuthnContext, Saml2Constants.ProtocolNamespace.OriginalString].GetElementOrNull<RequestedAuthnContext>();
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


    }
}