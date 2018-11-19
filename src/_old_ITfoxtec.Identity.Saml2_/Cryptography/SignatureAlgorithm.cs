using System;
using System.Security.Cryptography.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public static class SignatureAlgorithm
    {
        public static void ValidateAlgorithm(string signatureAlgorithm)
        {            
            if (SignedXml.XmlDsigRSASHA1Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (SignedXml.XmlDsigRSASHA256Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (SignedXml.XmlDsigRSASHA384Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }
            else if (SignedXml.XmlDsigRSASHA512Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return;
            }

            throw new NotSupportedException($"Only SHA1 ({SignedXml.XmlDsigRSASHA1Url}), SHA256 ({SignedXml.XmlDsigRSASHA256Url}), SHA384 ({SignedXml.XmlDsigRSASHA384Url}) and SHA512 ({SignedXml.XmlDsigRSASHA512Url}) is supported.");
        }

        public static string DigestMethod(string signatureAlgorithm)
        {
            if (SignedXml.XmlDsigRSASHA1Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SignedXml.XmlDsigSHA1Url;
            }
            else if (SignedXml.XmlDsigRSASHA256Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SignedXml.XmlDsigSHA256Url;
            }
            else if (SignedXml.XmlDsigRSASHA384Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SignedXml.XmlDsigSHA384Url;
            }
            else if (SignedXml.XmlDsigRSASHA512Url.Equals(signatureAlgorithm, StringComparison.InvariantCulture))
            {
                return SignedXml.XmlDsigSHA512Url;
            }
            else
            {
                ValidateAlgorithm(signatureAlgorithm);
                throw new InvalidOperationException();
            }
        }
    }
}
