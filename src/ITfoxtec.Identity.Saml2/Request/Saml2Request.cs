using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.Cryptography;
using Schemas = ITfoxtec.Identity.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using System.Security.Cryptography.Xml;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Generic Saml2 Request.
    /// </summary>
    public abstract class Saml2Request
    {        
        public Saml2Configuration Config { get; protected set; }

        public XmlDocument XmlDocument { get; protected set; }

        /// <summary>
        /// [Required]
        /// An identifier for the request. It is of type xs:ID and MUST follow the requirements specified in Section
        /// 1.3.4 for identifier uniqueness. The values of the ID attribute in a request and the InResponseTo
        /// attribute in the corresponding response MUST match.
        /// </summary>
        /// <value>The ID.</value>
        public Saml2Id Id { get; set; }

        /// <summary>
        /// The ID as string.
        /// </summary>
        /// <value>The ID string.</value>
        public string IdAsString
        {
            get { return Id.Value; }
            set { Id = new Saml2Id(value); }
        }

        /// <summary>
        /// [Required]
        /// The version of this request. The identifier for the version of SAML defined in this specification is "2.0".
        /// SAML versioning is discussed in Section 4.
        /// </summary>
        public string Version { get; set; }

        /// <summary>
        /// [Required]
        /// The time instant of issue of the request. The time value is encoded in UTC, as described in Section 1.3.3.
        /// </summary>
        public DateTimeOffset IssueInstant { get; set; }

        /// <summary>
        /// [Optional]
        /// A URI reference indicating the address to which this request has been sent. This is useful to prevent
        /// malicious forwarding of requests to unintended recipients, a protection that is required by some
        /// protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
        /// location at which the message was received. If it does not, the request MUST be discarded. Some
        /// protocol bindings may require the use of this attribute (see [SAMLBind]).
        /// </summary>
        public Uri Destination { get; set; }

        /// <summary>
        /// [Optional]
        /// Indicates whether or not (and under what conditions) consent has been obtained from a principal in
        /// the sending of this request. See Section 8.4 for some URI references that MAY be used as the value
        /// of the Consent attribute and their associated descriptions. If no Consent value is provided, the
        /// identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect.
        /// </summary>
        public string Consent { get; set; }

        /// <summary>
        /// [Optional]
        /// Identifies the entity that generated the response message. (For more information on this element, see
        /// Section 2.2.5.)
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// [Optional]
        /// This extension point contains optional protocol message extension elements that are agreed on between 
        /// the communicating parties. No extension schema is required in order to make use of this extension point, 
        /// and even if one is provided, the lax validation setting does not impose a requirement for the extension 
        /// to be valid.
        /// </summary>
        public Schemas.Extensions Extensions { get; set; }

        /// <summary>
        /// [Required in Logout Request otherwise Optional]
        /// The identifier and associated attributes (in plaintext or encrypted form) that specify the principal as
        /// currently recognized by the identity and service providers prior to this request. (For more information
        /// on this element, see Section 2.2.)
        /// </summary>
        public Saml2NameIdentifier NameId { get; set; }

        /// <summary>
        /// [Optional]
        /// The identifier that indexes this session at the message recipient.
        /// </summary>
        public string SessionIndex { get; set; }

        public IEnumerable<X509Certificate2> SignatureValidationCertificates { get; set; }

        public string SignatureAlgorithm { get; set; }     

        internal Saml2IdentityConfiguration IdentityConfiguration { get; private set; }

        public Saml2Request(Saml2Configuration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Config = config;
            Issuer = config.Issuer;
            IdentityConfiguration = Saml2IdentityConfiguration.GetIdentityConfiguration(config);

            Id = new Saml2Id();
            Version = Schemas.Saml2Constants.VersionNumber;
            IssueInstant = DateTimeOffset.UtcNow;
#if DEBUG
            Debug.WriteLine("Message ID: " + IdAsString);
#endif
        }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Schemas.Saml2Constants.ProtocolNamespaceNameX, Schemas.Saml2Constants.ProtocolNamespace.OriginalString);
            yield return new XAttribute(Schemas.Saml2Constants.AssertionNamespaceNameX, Schemas.Saml2Constants.AssertionNamespace.OriginalString);
            yield return new XAttribute(Schemas.Saml2Constants.Message.Id, IdAsString);
            yield return new XAttribute(Schemas.Saml2Constants.Message.Version, Version);
            yield return new XAttribute(Schemas.Saml2Constants.Message.IssueInstant, IssueInstant.UtcDateTime.ToString("o", CultureInfo.InvariantCulture));

            if (!string.IsNullOrWhiteSpace(Consent))
            {
                yield return new XAttribute(Schemas.Saml2Constants.Message.Consent, Consent);
            }

            if (Destination != null)
            {
                yield return new XAttribute(Schemas.Saml2Constants.Message.Destination, Destination);
            }

            if (Issuer != null)
            {
                yield return new XElement(Schemas.Saml2Constants.AssertionNamespaceX + Schemas.Saml2Constants.Message.Issuer, Issuer);
            }

            if (Extensions != null)
            {
                yield return Extensions.ToXElement();
            }            
        }

        public abstract XmlDocument ToXml();

        protected internal virtual void Read(string xml, bool validateXmlSignature)
        {
#if DEBUG
            Debug.WriteLine("Saml2P: " + xml);
#endif

            XmlDocument = xml.ToXmlDocument();

            if (XmlDocument.DocumentElement.NamespaceURI != Schemas.Saml2Constants.ProtocolNamespace.OriginalString)
            {
                throw new Saml2RequestException("Not SAML2 Protocol.");
            }

            ValidateElementName();

            Id = XmlDocument.DocumentElement.Attributes[Schemas.Saml2Constants.Message.Id].GetValueOrNull<Saml2Id>();

            Version = XmlDocument.DocumentElement.Attributes[Schemas.Saml2Constants.Message.Version].GetValueOrNull<string>();
            if (Version != Schemas.Saml2Constants.VersionNumber)
            {
                throw new Saml2RequestException("Invalid SAML2 version.");
            }

            IssueInstant = XmlDocument.DocumentElement.Attributes[Schemas.Saml2Constants.Message.IssueInstant].GetValueOrNull<DateTimeOffset>();

            Issuer = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Issuer, Schemas.Saml2Constants.AssertionNamespace.OriginalString].GetValueOrNull<string>();

            Destination = XmlDocument.DocumentElement.Attributes[Schemas.Saml2Constants.Message.Destination].GetValueOrNull<Uri>();

            var extensionsData = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Extensions, Schemas.Saml2Constants.ProtocolNamespace.OriginalString].GetValueOrNull<string>();
            if (extensionsData != null)
            {
                Extensions = new Schemas.Extensions { Data = extensionsData };
            }

            var documentValidationResult = MustValidateXmlSignature(validateXmlSignature) ? ValidateXmlSignature(XmlDocument.DocumentElement) : SignatureValidation.NotPresent;

            DecryptMessage();

            if (MustValidateXmlSignature(validateXmlSignature))
            {
                ValidateXmlSignature(documentValidationResult);
            }
        }

        protected abstract void ValidateElementName();

        protected virtual void DecryptMessage()
        { }

        protected virtual XmlElement GetAssertionElement()
        {
            return null;
        }

        private bool MustValidateXmlSignature(bool validateXmlSignature)
        {
            return !(this is Saml2AuthnRequest) && validateXmlSignature;
        }

        private void ValidateXmlSignature(SignatureValidation documentValidationResult)
        {
            var assertionElement = GetAssertionElement();
            if(assertionElement == null)
            {
                if (documentValidationResult != SignatureValidation.Valid)
                    throw new InvalidSignatureException("Signature is invalid.");                
            }
            else
            {                
                var assertionValidationResult = ValidateXmlSignature(assertionElement);
                if (documentValidationResult == SignatureValidation.Invalid || assertionValidationResult == SignatureValidation.Invalid || 
                    !(documentValidationResult == SignatureValidation.Valid || assertionValidationResult == SignatureValidation.Valid))
                    throw new InvalidSignatureException("Signature is invalid.");
            }            
        }

        protected SignatureValidation ValidateXmlSignature(XmlElement xmlElement)
        {
            var xmlSignatures = xmlElement.SelectNodes($"*[local-name()='{Schemas.Saml2Constants.Message.Signature}' and namespace-uri()='{SignedXml.XmlDsigNamespaceUrl}']");
            if(xmlSignatures.Count == 0)
            {
                return SignatureValidation.NotPresent;
            }
            if (xmlSignatures.Count > 1)
            {
                throw new InvalidSignatureException("There is more then one Signature element.");
            }

            foreach (var signatureValidationCertificate in SignatureValidationCertificates)
            {
                IdentityConfiguration.CertificateValidator.Validate(signatureValidationCertificate);

                var signedXml = new Saml2SignedXml(xmlElement, signatureValidationCertificate, SignatureAlgorithm);
                signedXml.LoadXml(xmlSignatures[0] as XmlElement);
                if (signedXml.CheckSignature())
                {
                    // Signature is valid.
                    return SignatureValidation.Valid;
                }
            }
            return SignatureValidation.Invalid;
        }

        protected enum SignatureValidation
        {
            Valid,
            Invalid,
            NotPresent
        }
    }
}
