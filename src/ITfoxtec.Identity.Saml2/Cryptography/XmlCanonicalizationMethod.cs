using System;
using System.Security.Cryptography.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public static class XmlCanonicalizationMethod
    {
        public static void ValidateCanonicalizationMethod(string xmlCanonicalizationMethod)
        {
            if (xmlCanonicalizationMethod == SignedXml.XmlDsigExcC14NTransformUrl || xmlCanonicalizationMethod == SignedXml.XmlDsigExcC14NWithCommentsTransformUrl)
            {
                return;
            }

            throw new NotSupportedException($"Only XML canonicalization method {SignedXml.XmlDsigExcC14NTransformUrl} and {SignedXml.XmlDsigExcC14NWithCommentsTransformUrl} is supported.");
        }

        public static XmlDsigExcC14NTransform GetTransform(string xmlCanonicalizationMethod)
        {
            ValidateCanonicalizationMethod(xmlCanonicalizationMethod);

            if (xmlCanonicalizationMethod == SignedXml.XmlDsigExcC14NWithCommentsTransformUrl)
            {
                return new XmlDsigExcC14NWithCommentsTransform();
            }
            else
            {
                return new XmlDsigExcC14NTransform();
            }
        }
    }
}
