#if !NETFULL
using ITfoxtec.Identity.Saml2.Cryptography;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tokens
{
    internal class Saml2TokenSerializer : Saml2Serializer
    {
        private readonly IEnumerable<X509Certificate2> decryptionCertificates;

        public Saml2TokenSerializer(IEnumerable<X509Certificate2> decryptionCertificates) : base() 
        {
            this.decryptionCertificates = decryptionCertificates;
        }

        protected override Saml2NameIdentifier ReadEncryptedId(XmlDictionaryReader reader)
        {
            if (decryptionCertificates?.Count() > 0)
            {
                var xmlDocument = reader.ReadOuterXml().ToXmlDocument();

                var exceptions = new List<Exception>();
                foreach (var decryptionCertificate in decryptionCertificates)
                {
                    try
                    {
                        new Saml2EncryptedXml(xmlDocument, decryptionCertificate.GetSamlRSAPrivateKey()).DecryptDocument();
                        // Stop the look when the message successfully decrypted.
                        var decryptedReader = XmlDictionaryReader.CreateDictionaryReader(new XmlNodeReader(xmlDocument.DocumentElement.FirstChild));
                        return ReadNameIdentifier(decryptedReader, null);
                    }
                    catch (Exception e)
                    {
                        exceptions.Add(e);
                    }
                }
                throw new AggregateException("Failed to decrypt message", exceptions);
            }
            else
            {
                return base.ReadEncryptedId(reader);
            }
        }

        // Coped from Saml2Serializer. Resolving not supporting empty/null classRef bug. 
        protected override Saml2AuthenticationContext ReadAuthenticationContext(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthnContext, Saml2Constants.Namespace);
            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthnContextType, Saml2Constants.Namespace);

                if (reader.IsEmptyElement)
                    throw new Saml2SecurityTokenReadException(/*LogMessages.IDX13312*/"IDX13312: 'AuthnContext' cannot be empty.");

                // Content
                reader.ReadStartElement();

                // At least one of ClassRef and ( Decl XOR DeclRef) must be present
                // At this time, we do not support Decl, which is a by-value 
                // authentication context declaration.
                Uri classRef = null;
                Uri declRef = null;

                // <AuthnContextClassRef> - see comment above
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextClassRef, Saml2Constants.Namespace))
                    classRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextClassRef, UriKind.RelativeOrAbsolute, false);

                // <AuthnContextDecl> - see comment above
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDecl, Saml2Constants.Namespace))
                    throw new Saml2SecurityTokenReadException(/*LogMessages.IDX13118*/"IDX13118: A <saml:AuthnContextDecl> element was encountered.To handle by-value authentication context declarations, extend Saml2SecurityTokenHandler and override ReadAuthenticationContext.In addition, it may be necessary to extend Saml2AuthenticationContext so that its data model can accommodate the declaration value.");

                // <AuthnContextDeclRef> - see comment above
                // If there was no ClassRef, there must be a DeclRef
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace))
                    declRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextDeclRef, UriKind.RelativeOrAbsolute, false);
                else if (classRef == null)
                    reader.ReadStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace);

                // Now we have enough data to create the object
                var authnContext = new Saml2AuthenticationContext();

                if (classRef != null)
                    authnContext.ClassReference = classRef;

                if (declRef != null)
                    authnContext.DeclarationReference = declRef;

                // <AuthenticatingAuthority> - 0-OO
                while (reader.IsStartElement(Saml2Constants.Elements.AuthenticatingAuthority, Saml2Constants.Namespace))
                    authnContext.AuthenticatingAuthorities.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthenticatingAuthority, UriKind.RelativeOrAbsolute, false));

                reader.ReadEndElement();
                return authnContext;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw new Saml2SecurityTokenReadException(/*LogMessages.IDX13102*/"IDX13102: Exception thrown while reading 'AuthnContext' for Saml2SecurityToken.", ex);
            }
        }

        // Coped from Saml2Serializer
        internal static Uri ReadSimpleUriElement(XmlDictionaryReader reader, string element, UriKind kind, bool requireUri)
        {
            try
            {
                if (reader.IsEmptyElement)
                    throw new Saml2SecurityTokenReadException(/*LogMessages.IDX13104*/"IDX13104: Unable to read Saml2SecurityToken. Expecting XmlReader to be at element: 'Uri', found 'Empty Element'");

                XmlUtil.ValidateXsiType(reader, XmlSignatureConstants.Attributes.AnyUri, XmlSignatureConstants.XmlSchemaNamespace);
                reader.MoveToElement();
                string value = reader.ReadElementContentAsString();

                if (string.IsNullOrEmpty(value))
                    throw new Saml2SecurityTokenReadException(/*LogMessages.IDX13136*/$"IDX13136: Unable to read for Saml2SecurityToken. Required Element: '{element}' is missing or empty.");

                if (requireUri && !Uri.TryCreate(value, kind, out Uri tempUri))
                    throw new Saml2SecurityTokenReadException(/*LogMessages.IDX13107*/$"IDX13107: When reading '{element}', '{element}' was not a Absolute Uri, was: '{value}'.");

                return new Uri(value, kind);
            }
            catch (Exception ex)
            {
                throw new Saml2SecurityTokenReadException(/*LogMessages.IDX13102*/$"IDX13102: Exception thrown while reading '{element}' for Saml2SecurityToken.", ex);
            }
        }
    }
}
#endif
