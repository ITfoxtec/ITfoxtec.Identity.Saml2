using System.Collections.Generic;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Metadata
{
    /// <summary>
    /// EncryptionMethod is an optional element that describes the encryption algorithm applied to the cipher data. 
    /// If the element is absent, the encryption algorithm must be known to the recipient or the decryption will fail.
    /// </summary>
    public class EncryptionMethodType
    {
        const string elementName = Saml2MetadataConstants.Message.EncryptionMethod;

        /// <summary>
        /// [Required]
        /// the Algorithm attribute URI.
        /// </summary>
        public string Algorithm { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            if (Algorithm != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.Algorithm, Algorithm);
            }
        }
    }
}
