using Schemas = ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Tokens;
using System;
using System.Linq;
using System.Security.Claims;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Cryptography;
using System.Diagnostics;
using System.Collections.Generic;
using System.Xml.Linq;
#if NETFULL
using System.IdentityModel.Tokens;
using System.IdentityModel.Protocols.WSTrust;
#else
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
#endif


namespace ITfoxtec.Identity.Saml2
{
    /// <summary>
    /// Saml2 Authn Response.
    /// </summary>
    public class Saml2AuthnResponse : Saml2Response
    {

        const string elementName = Schemas.Saml2Constants.Message.AuthnResponse;

        internal X509Certificate2 DecryptionCertificate { get; private set; }

        /// <summary>
        /// Claims Identity.
        /// </summary>
        public ClaimsIdentity ClaimsIdentity { get; set; }

        /// <summary>
        /// Saml2 Security Token.
        /// </summary>
        public Saml2SecurityToken Saml2SecurityToken { get; protected set; }

        /// <summary>
        /// Gets the first instant in time at which this security token is valid.
        /// </summary>
        public DateTimeOffset SecurityTokenValidFrom { get { return Saml2SecurityToken.ValidFrom.ToDateTimeOffsetOutOfRangeProtected(); } }

        /// <summary>
        /// Gets the last instant in time at which this security token is valid.
        /// </summary>
        public DateTimeOffset SecurityTokenValidTo { get { return Saml2SecurityToken.ValidTo.ToDateTimeOffsetOutOfRangeProtected(); } }

        /// <summary>
        /// Saml2 Security Token Handler.
        /// </summary>
        public Saml2ResponseSecurityTokenHandler Saml2SecurityTokenHandler { get; protected set; }

        public Saml2AuthnResponse(Saml2Configuration config) : base(config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Destination = config.SingleSignOnDestination;

            if (config.DecryptionCertificate != null)
            {
                DecryptionCertificate = config.DecryptionCertificate;
                if (config.DecryptionCertificate.GetSamlRSAPrivateKey() == null)
                {
                    throw new ArgumentException("No RSA Private Key present in Decryption Certificate or missing private key read credentials.");
                }
            }
            Saml2SecurityTokenHandler = Saml2ResponseSecurityTokenHandler.GetSaml2SecurityTokenHandler(IdentityConfiguration);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2RequestException("Not a SAML2 Authn Response.");
            }
        }

        /// <summary>
        /// Creates the Security Token and add it to the response.
        /// </summary>
        /// <param name="appliesToAddress">The address for the AppliesTo property in the RequestSecurityTokenResponse.</param>
        /// <param name="authnContext">The URI reference that identifies an authentication context class that describes the authentication context declaration that follows. [Saml2Core, 2.7.2.2]</param>
        /// <param name="subjectConfirmationLifetime">The Subject Confirmation Lifetime in minutes.</param>
        /// <param name="issuedTokenLifetime">The Issued Token Lifetime in minutes.</param>
        /// <returns>The SAML 2.0 Security Token.</returns>
        public Saml2SecurityToken CreateSecurityToken(string appliesToAddress, Uri authnContext = null, int subjectConfirmationLifetime = 5, int issuedTokenLifetime = 60)
        {
            if (appliesToAddress == null) throw new ArgumentNullException(nameof(appliesToAddress));
            if (ClaimsIdentity == null) throw new ArgumentNullException("ClaimsIdentity property");

            var tokenDescriptor = CreateTokenDescriptor(ClaimsIdentity.Claims, appliesToAddress, issuedTokenLifetime);
            Saml2SecurityToken = Saml2SecurityTokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            AddNameIdFormat();
            AddAuthenticationStatement(CreateAuthenticationStatement(authnContext));
            AddSubjectConfirmation(CreateSubjectConfirmation(subjectConfirmationLifetime));

            return Saml2SecurityToken;
        }

        /// <summary>
        /// Creates the Security Token and add it to the response.
        /// </summary>
        /// <param name="tokenDescriptor">This is a place holder for all the attributes related to the issued token.</param>
        /// <param name="authenticationStatement">Represents the AuthnStatement element specified in [Saml2Core, 2.7.2].</param>
        /// <param name="subjectConfirmation">Represents the SubjectConfirmation element specified in [Saml2Core, 2.4.1.1].</param>
        /// <returns>The SAML 2.0 Security Token.</returns>
        public Saml2SecurityToken CreateSecurityToken(SecurityTokenDescriptor tokenDescriptor, Saml2AuthenticationStatement authenticationStatement, Saml2SubjectConfirmation subjectConfirmation)
        {
            if (tokenDescriptor == null) throw new ArgumentNullException(nameof(tokenDescriptor));
            if (authenticationStatement == null) throw new ArgumentNullException(nameof(authenticationStatement));
            if (subjectConfirmation == null) throw new ArgumentNullException(nameof(subjectConfirmation));

            Saml2SecurityToken = Saml2SecurityTokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            AddNameIdFormat();
            AddAuthenticationStatement(authenticationStatement);
            AddSubjectConfirmation(subjectConfirmation);

            return Saml2SecurityToken;
        }

        protected virtual SecurityTokenDescriptor CreateTokenDescriptor(IEnumerable<Claim> claims, string appliesToAddress, int issuedTokenLifetime)
        {
            if (string.IsNullOrEmpty(Issuer)) throw new ArgumentNullException("Issuer property");

            var now = DateTimeOffset.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor();
            tokenDescriptor.Subject = new ClaimsIdentity(claims.Where(c => c.Type != ClaimTypes.NameIdentifier));
#if NETFULL
            tokenDescriptor.TokenType = Schemas.SamlTokenTypes.Saml2TokenProfile11.OriginalString;
            tokenDescriptor.Lifetime = new Lifetime(now.UtcDateTime, now.AddMinutes(issuedTokenLifetime).UtcDateTime);
            tokenDescriptor.AppliesToAddress = appliesToAddress;
            tokenDescriptor.TokenIssuerName = Issuer;
#else
            tokenDescriptor.Expires = now.AddMinutes(issuedTokenLifetime).UtcDateTime;
            tokenDescriptor.Audience = appliesToAddress;
            tokenDescriptor.Issuer = Issuer;
#endif
            return tokenDescriptor;
        }

        protected virtual Saml2SubjectConfirmation CreateSubjectConfirmation(int subjectConfirmationLifetime)
        {
            if (Destination == null) throw new ArgumentNullException("Destination property");

            var subjectConfirmationData = new Saml2SubjectConfirmationData
            {
                Recipient = Destination,
                NotOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(subjectConfirmationLifetime).UtcDateTime,
            };

            if (InResponseTo != null)
            {
                subjectConfirmationData.InResponseTo = InResponseTo;
            }

            return new Saml2SubjectConfirmation(Schemas.Saml2Constants.Saml2BearerToken, subjectConfirmationData);
        }

        protected virtual Saml2AuthenticationStatement CreateAuthenticationStatement(Uri authnContext)
        {
            var authenticationStatement = new Saml2AuthenticationStatement(new Saml2AuthenticationContext(authnContext ?? Schemas.AuthnContextClassTypes.PasswordProtectedTransport));
            authenticationStatement.SessionIndex = SessionIndex;
            return authenticationStatement;
        }

        private void AddNameIdFormat()
        {
            if (NameId == null) throw new ArgumentNullException("NameId property");

            Saml2SecurityToken.Assertion.Subject.NameId = NameId;
            if (Saml2SecurityToken.Assertion.Subject.NameId.Format == null)
            {
                Saml2SecurityToken.Assertion.Subject.NameId.Format = Schemas.NameIdentifierFormats.Persistent;
            }
        }

        private void AddSubjectConfirmation(Saml2SubjectConfirmation subjectConfirmation)
        {
            Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Clear();
            Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Add(subjectConfirmation);
        }

        private void AddAuthenticationStatement(Saml2AuthenticationStatement authenticationStatement)
        {
            Saml2SecurityToken.Assertion.Statements.Add(authenticationStatement);
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + elementName);
            envelope.Add(base.GetXContent());
            XmlDocument = envelope.ToXmlDocument();

            if (Saml2SecurityToken != null)
            {
                var tokenXml = Saml2SecurityTokenHandler.WriteToken(Saml2SecurityToken);

                var status = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Status, Schemas.Saml2Constants.ProtocolNamespace.OriginalString];
                XmlDocument.DocumentElement.InsertAfter(XmlDocument.ImportNode(tokenXml.ToXmlDocument().DocumentElement, true), status);
            }

            return XmlDocument;
        }

        protected internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, validateXmlSignature);

            if (Status == Schemas.Saml2StatusCodes.Success)
            {
                var assertionElement = GetAssertionElement();
                ValidateAssertionExpiration(assertionElement);

#if NETFULL
                Saml2SecurityToken = ReadSecurityToken(assertionElement);
                ClaimsIdentity = ReadClaimsIdentity();
#else
                var tokenString = assertionElement.OuterXml;
                Saml2SecurityToken = ReadSecurityToken(tokenString);
                ClaimsIdentity = ReadClaimsIdentity(tokenString);
#endif
            }
        }

        XmlElement assertionElement = null;
        protected override XmlElement GetAssertionElement()
        {
            if (assertionElement == null)
            {
                var assertionElements = XmlDocument.DocumentElement.SelectNodes($"//*[local-name()='{Schemas.Saml2Constants.Message.Assertion}']");
                if (assertionElements.Count != 1)
                {
                    throw new Saml2RequestException("There is not exactly one Assertion element.");
                }
                assertionElement = (assertionElements[0] as XmlElement).ToXmlDocument().DocumentElement;
            }            
            return assertionElement;            
        }

        private void ValidateAssertionExpiration(XmlNode assertionElement)
        {
            var subjectElement = assertionElement[Schemas.Saml2Constants.Message.Subject, Schemas.Saml2Constants.AssertionNamespace.OriginalString];
            if (subjectElement == null)
            {
                throw new Saml2RequestException("Subject Not Found.");
            }

            var subjectConfirmationElement = subjectElement[Schemas.Saml2Constants.Message.SubjectConfirmation, Schemas.Saml2Constants.AssertionNamespace.OriginalString];
            if (subjectConfirmationElement == null)
            {
                throw new Saml2RequestException("SubjectConfirmationElement Not Found.");
            }

            var subjectConfirmationData = subjectConfirmationElement[Schemas.Saml2Constants.Message.SubjectConfirmationData, Schemas.Saml2Constants.AssertionNamespace.OriginalString];
            if (subjectConfirmationData == null)
            {
                throw new Saml2RequestException("SubjectConfirmationData Not Found.");
            }

            var notOnOrAfter = subjectConfirmationData.Attributes[Schemas.Saml2Constants.Message.NotOnOrAfter].GetValueOrNull<DateTimeOffset>();
            if (notOnOrAfter < DateTimeOffset.UtcNow)
            {
                throw new Saml2RequestException($"Assertion has expired. Assertion valid NotOnOrAfter {notOnOrAfter}.");
            }
        }

#if NETFULL
        private Saml2SecurityToken ReadSecurityToken(XmlNode assertionElement)
        {
            using (var reader = new XmlNodeReader(assertionElement))
            {
                return Saml2SecurityTokenHandler.ReadToken(reader) as Saml2SecurityToken;
            }
        }

        private ClaimsIdentity ReadClaimsIdentity()
        {
            return Saml2SecurityTokenHandler.ValidateToken(Saml2SecurityToken, this).First();
        }
#else
        private Saml2SecurityToken ReadSecurityToken(string tokenString)
        {
            return Saml2SecurityTokenHandler.ReadSaml2Token(tokenString);
        }

        private ClaimsIdentity ReadClaimsIdentity(string tokenString)
        {
            return Saml2SecurityTokenHandler.ValidateToken(Saml2SecurityToken, tokenString, this).First();
        }
#endif

        protected override void DecryptMessage()
        {
            if (DecryptionCertificate != null)
            {
                new Saml2EncryptedXml(XmlDocument, DecryptionCertificate.GetSamlRSAPrivateKey()).DecryptDocument();
#if DEBUG
                Debug.WriteLine("Saml2P (Decrypted): " + XmlDocument.OuterXml);
#endif
            }
        }
    }
}
