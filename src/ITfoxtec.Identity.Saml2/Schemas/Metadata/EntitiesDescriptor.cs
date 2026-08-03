using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using System.Text.RegularExpressions;
#if NETFULL
using System.IdentityModel.Tokens;
#else
using Microsoft.IdentityModel.Tokens.Saml2;
#endif

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The EntitiesDescriptor element contains the metadata for an optionally named group of SAML entities.
    /// </summary>
    public class EntitiesDescriptor
    {
        const string elementName = Saml2MetadataConstants.Message.EntitiesDescriptor;

        public Saml2Configuration Config { get; protected set; }

        /// <summary>
        /// [Optional]
        /// A document-unique identifier for the element, typically used as a reference point when signing.
        /// </summary>
        public Saml2Id Id { get; protected set; }

        /// <summary>
        /// The ID as string.
        /// </summary>
        /// <value>The ID string.</value>
        public string IdAsString
        {
            get { return Id?.Value; }
        }

        /// <summary>
        /// [Optional]
        /// A string name that identifies a group of SAML entities in the context of some deployment.
        /// </summary>
        public string Name { get; protected set; }

        /// <summary>
        /// [Optional]
        /// Optional attribute indicates the expiration time of the metadata contained in the element and any contained elements.
        /// Metadata is valid until in days from now.
        /// </summary>
        public int? ValidUntil { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional attribute indicates how long a metadata consumer should cache this metadata before attempting to re-fetch.
        /// Value must be an XML Schema duration (https://www.w3.org/TR/xmlschema-2/#duration). Example: P1D, PT12H, P2Y3M.
        /// Regex used for validation: ^-?P(\d*Y)?(\d*M)?(\d*D)?(T(\d*H)?(\d*M)?(\d*S)?)?$
        /// Throws <see cref="ArgumentException"/> if set to a non-empty value that does not match the duration pattern.
        /// </summary>
        public string CacheDuration
        {
            get => _cacheDuration;
            set
            {
                if(!string.IsNullOrEmpty(value) && !CacheDurationRegex.IsMatch(value))
                {
                    throw new ArgumentException($"Invalid cacheDuration format. See https://www.w3.org/TR/xmlschema-2/#duration. Value: '{value}'");
                }
                _cacheDuration = value;
            }
        }

        private string _cacheDuration;
    // Require at least one date or time component after 'P' using a lookahead. See https://www.w3.org/TR/xmlschema-2/#duration
    private static readonly Regex CacheDurationRegex = new Regex(@"^-?P(?=\d|T)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$", RegexOptions.Compiled);

        /// <summary>
        /// [Optional]
        /// An metadata XML signature that authenticates the containing element and its contents.
        /// </summary>
        public X509Certificate2 MetadataSigningCertificate { get; protected set; }

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// [One or More]
        /// Contains the metadata for one or more SAML entities.
        /// </summary>
        public IEnumerable<EntityDescriptor> EntityDescriptorList { get; protected set; }

        /// <summary>
        /// [Optional]
        /// This extension point contains optional metadata extension XML elements that are agreed on between 
        /// the communicating parties. No extension schema is required in order to make use of this extension point, 
        /// and even if one is provided, the lax validation setting does not impose a requirement for the extension 
        /// to be valid. SAML extension elements MUST be namespace-qualified in a non-SAML-defined namespace.
        /// </summary>
        public Extensions Extensions { get; set; }

        public EntitiesDescriptor()
        { }

        public EntitiesDescriptor(Saml2Configuration config, IEnumerable<EntityDescriptor> entitiesDescriptor, string name = null, bool signMetadata = true) : this()
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            Config = config;
            Id = new Saml2Id();
            Name = name;
            EntityDescriptorList = entitiesDescriptor;
            if (signMetadata)
            {
                MetadataSigningCertificate = config.SigningCertificate;
                CertificateIncludeOption = X509IncludeOption.EndCertOnly;
            }
        }

        public XmlDocument ToXmlDocument()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());
            var xmlDocument = envelope.ToXmlDocument();
            if(MetadataSigningCertificate != null)
            {
                xmlDocument.SignDocument(MetadataSigningCertificate, Config.SignatureAlgorithm, Config.XmlCanonicalizationMethod, CertificateIncludeOption, IdAsString, Config.IncludeKeyInfoName);
            }
            return xmlDocument;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Id, IdAsString);
            if(Name != null)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.Name, Name);
            }
            if (ValidUntil.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.ValidUntil, DateTimeOffset.UtcNow.AddDays(ValidUntil.Value).UtcDateTime.ToString(Saml2Constants.DateTimeFormat, CultureInfo.InvariantCulture));
            }
            if (!string.IsNullOrEmpty(CacheDuration))
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.CacheDuration, CacheDuration);
            }
            yield return new XAttribute(Saml2MetadataConstants.MetadataNamespaceNameX, Saml2MetadataConstants.MetadataNamespace);

            if (Extensions != null) 
            {
                yield return Extensions.ToXElement();
            }
            
            if (EntityDescriptorList != null)
            {
                foreach( var entityDescriptor in EntityDescriptorList)
                {
                    yield return entityDescriptor.ToXElement();
                }
            }
        }
    }
}
