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
        public override string ElementName => Schemas.Saml2Constants.Message.AuthnResponse;

        internal IEnumerable<X509Certificate2> DecryptionCertificates { get; private set; }
        internal X509Certificate2 EncryptionCertificate { get; private set; }

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

            if (config.DecryptionCertificates?.Count() > 0)
            {
                DecryptionCertificates = config.DecryptionCertificates.Where(c => c.GetSamlRSAPrivateKey() != null);
                if (!(DecryptionCertificates?.Count() > 0))
                {
                    throw new ArgumentException("No RSA Private Key present in Decryption Certificates or missing private key read credentials.");
                }
            }
            if (config.EncryptionCertificate != null)
            {
                EncryptionCertificate = config.EncryptionCertificate;
                if (config.EncryptionCertificate.GetRSAPublicKey() == null)
                {
                    throw new ArgumentException("No RSA Public Key present in Encryption Certificate.");
                }
            }
            Saml2SecurityTokenHandler = Saml2ResponseSecurityTokenHandler.GetSaml2SecurityTokenHandler(IdentityConfiguration);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != ElementName)
            {
                throw new Saml2RequestException("Not a SAML2 Authn Response.");
            }
        }

        /// <summary>
        /// Creates the Security Token and add it to the response.
        /// </summary>
        /// <param name="appliesToAddress">The address for the AppliesTo property in the RequestSecurityTokenResponse.</param>
        /// <param name="authnContext">The URI reference that identifies an authentication context class that describes the authentication context declaration that follows. [Saml2Core, 2.7.2.2]</param>
        /// <param name="declAuthnContext">The declaration URI reference of the authentication context class that describes the authentication context declaration. [Saml2Core, 2.7.2.2]</param>
        /// <param name="subjectConfirmationLifetime">The Subject Confirmation Lifetime in minutes.</param>
        /// <param name="issuedTokenLifetime">The Issued Token Lifetime in minutes.</param>
        /// <returns>The SAML 2.0 Security Token.</returns>
        public Saml2SecurityToken CreateSecurityToken(string appliesToAddress, Uri authnContext = null, Uri declAuthnContext = null, int subjectConfirmationLifetime = 5, int issuedTokenLifetime = 60)
        {
            if (appliesToAddress == null) throw new ArgumentNullException(nameof(appliesToAddress));
            if (ClaimsIdentity == null) throw new ArgumentNullException("ClaimsIdentity property");

            var tokenDescriptor = CreateTokenDescriptor(ClaimsIdentity.Claims, appliesToAddress, issuedTokenLifetime);
            Saml2SecurityToken = Saml2SecurityTokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            AddNameIdFormat(ClaimsIdentity.Claims);
            AddAuthenticationStatement(CreateAuthenticationStatement(authnContext, declAuthnContext));
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

        protected virtual Saml2AuthenticationStatement CreateAuthenticationStatement(Uri authnContext, Uri declAuthnContext)
        {
            var saml2AuthenticationContext = new Saml2AuthenticationContext();
            if (authnContext == null && declAuthnContext == null)
            {
                saml2AuthenticationContext.ClassReference = Schemas.AuthnContextClassTypes.PasswordProtectedTransport;
            }
            else
            {
                if (authnContext != null)
                {
                    saml2AuthenticationContext.ClassReference = authnContext;
                }
                if (declAuthnContext != null)
                {
                    saml2AuthenticationContext.DeclarationReference = declAuthnContext;
                }
            }
            var authenticationStatement = new Saml2AuthenticationStatement(saml2AuthenticationContext);
            authenticationStatement.SessionIndex = SessionIndex;
            return authenticationStatement;
        }

        private void AddNameIdFormat(IEnumerable<Claim> claims = null)
        {
            if (NameId != null)
            {
                Saml2SecurityToken.Assertion.Subject.NameId = NameId;
            }
            else if (claims != null)
            {
                var nameIdValue = claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).FirstOrDefault();
                if (!string.IsNullOrEmpty(nameIdValue))
                {
                    Saml2SecurityToken.Assertion.Subject.NameId = new Saml2NameIdentifier(nameIdValue);
                }
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
            var envelope = new XElement(Schemas.Saml2Constants.ProtocolNamespaceX + ElementName);
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

        protected internal void SignAuthnResponseAssertion(X509IncludeOption certificateIncludeOption)
        {
            if (Status != Schemas.Saml2StatusCodes.Success)
            {
                return;
            }

            Cryptography.SignatureAlgorithm.ValidateAlgorithm(Config.SignatureAlgorithm);
            Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(Config.XmlCanonicalizationMethod);
            XmlDocument.SignAssertion(GetAssertionElementReference(), Config.SigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, certificateIncludeOption, Config.IncludeKeyInfoName);
        }

        protected internal override void Read(string xml, bool validate = false, bool detectReplayedTokens = true)
        {
            base.Read(xml, validate, detectReplayedTokens);

            if (Status == Schemas.Saml2StatusCodes.Success)
            {
                var assertionElement = GetAssertionElement();
                ValidateAssertionSubject(assertionElement);

#if NETFULL
                Saml2SecurityToken = ReadSecurityToken(assertionElement);
                ClaimsIdentity = ReadClaimsIdentity(detectReplayedTokens);
#else
                var tokenString = assertionElement.OuterXml;
                Saml2SecurityToken = ReadSecurityToken(tokenString);
                ClaimsIdentity = ReadClaimsIdentity(tokenString, detectReplayedTokens);
#endif
            }
        }

        XmlElement assertionElementCache = null;
        protected override XmlElement GetAssertionElement()
        {
            if (assertionElementCache == null)
            {
#if NETFULL || NETSTANDARD || NETCORE || NET50 || NET60
                assertionElementCache = GetAssertionElementReference().ToXmlDocument().DocumentElement;
#else
                assertionElementCache = GetAssertionElementReference();
#endif
            }
            return assertionElementCache;
        }

        protected XmlElement GetAssertionElementReference()
        {
            // Select all Assertion elements in the document that are at the top of their respective Assertion hierarchy.
            // If the document contains <Assertion><Assertion></Assertion></Assertion> only the outer (hierarchical parent) Assertion is selected.
            var assertionElements = XmlDocument.DocumentElement.SelectNodes($"//*[local-name()='{Schemas.Saml2Constants.Message.Assertion}']/ancestor-or-self::*[local-name()='{Schemas.Saml2Constants.Message.Assertion}'][last()]");
            if (assertionElements.Count != 1)
            {
                throw new Saml2RequestException("There is not exactly one Assertion element. Maybe the response is encrypted (set the Saml2Configuration.DecryptionCertificate).");
            }
            return assertionElements[0] as XmlElement;
        }

        private void ValidateAssertionSubject(XmlNode assertionElement)
        {
            var subjectElement = assertionElement[Schemas.Saml2Constants.Message.Subject, Schemas.Saml2Constants.AssertionNamespace.OriginalString];
            if (subjectElement == null)
            {
                throw new Saml2RequestException("Subject Not Found.");
            }

            ValidateSubjectConfirmationExpiration(subjectElement);
        }

        protected virtual void ValidateSubjectConfirmationExpiration(XmlElement subjectElement)
        {
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

        private ClaimsIdentity ReadClaimsIdentity(bool detectReplayedTokens)
        {
            return Saml2SecurityTokenHandler.ValidateToken(Saml2SecurityToken, this, detectReplayedTokens).First();
        }
#else
        private Saml2SecurityToken ReadSecurityToken(string tokenString)
        {
            return Saml2SecurityTokenHandler.ReadSaml2Token(tokenString);
        }

        private ClaimsIdentity ReadClaimsIdentity(string tokenString, bool detectReplayedTokens)
        {
            return Saml2SecurityTokenHandler.ValidateToken(Saml2SecurityToken, tokenString, this, detectReplayedTokens).First();
        }
#endif

        protected override void DecryptMessage()
        {
            if (DecryptionCertificates?.Count() > 0)
            {
                var exceptions = new List<Exception>();
                foreach (var decryptionCertificate in DecryptionCertificates)
                {
                    try
                    {
                        new Saml2EncryptedXml(XmlDocument, decryptionCertificate.GetSamlRSAPrivateKey()).DecryptDocument();
                        // Stop the look when the message successfully decrypted.
                        return;
                    }
                    catch (Exception e)
                    {
                        exceptions.Add(e);
                    }
                }
                throw new AggregateException("Failed to decrypt message", exceptions);
#if DEBUG
                Debug.WriteLine("Saml2P (Decrypted): " + XmlDocument.OuterXml);
#endif
            }
        }

        protected internal void EncryptMessage()
        {
            if (Status != Schemas.Saml2StatusCodes.Success)
            {
                return;
            }

            var envelope = new XElement(Schemas.Saml2Constants.AssertionNamespaceX + Schemas.Saml2Constants.Message.EncryptedAssertion);
            var status = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Status, Schemas.Saml2Constants.ProtocolNamespace.OriginalString];
            XmlDocument.DocumentElement.InsertAfter(XmlDocument.ImportNode(envelope.ToXmlDocument().DocumentElement, true), status);

            var assertionElement = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.Assertion, Schemas.Saml2Constants.AssertionNamespace.OriginalString];
            assertionElement.ParentNode.RemoveChild(assertionElement);

            var encryptedDataElement = new Saml2EncryptedXml(EncryptionCertificate.GetRSAPublicKey()).EncryptAassertion(assertionElement);

            var encryptedAssertionElement = XmlDocument.DocumentElement[Schemas.Saml2Constants.Message.EncryptedAssertion, Schemas.Saml2Constants.AssertionNamespace.OriginalString];
            encryptedAssertionElement.AppendChild(XmlDocument.ImportNode(encryptedDataElement, true));

#if DEBUG
            Debug.WriteLine("Saml2P (Encrypted): " + XmlDocument.OuterXml);
#endif
        }
    }
}
