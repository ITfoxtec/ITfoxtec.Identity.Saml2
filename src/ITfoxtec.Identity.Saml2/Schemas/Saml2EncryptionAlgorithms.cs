namespace ITfoxtec.Identity.Saml2.Schemas
{
    public static class Saml2EncryptionAlgorithms
    {
        public const string XmlEncNamespaceUrl = "http://www.w3.org/2001/04/xmlenc#";
        public const string XmlEncElementUrl = "http://www.w3.org/2001/04/xmlenc#Element";
        public const string XmlEncElementContentUrl = "http://www.w3.org/2001/04/xmlenc#Content";
        public const string XmlEncEncryptedKeyUrl = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

        // Symmetric Block Encryption
        public const string XmlEncAES128Url = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        public const string XmlEncAES192Url = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
        public const string XmlEncAES256Url = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
        public const string XmlEncAES128GCMUrl = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
        public const string XmlEncAES192GCMUrl = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
        public const string XmlEncAES256GCMUrl = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

        // Key Transport
        public const string XmlEncRSA15Url = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
        public const string XmlEncRSAOAEPUrl = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
        public const string XmlEncRSAOAEP11Url = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
        public const string XmlEncMGF1SHA1Url = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
        public const string XmlEncMGF1SHA256Url = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
        public const string XmlEncMGF1SHA384Url = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
        public const string XmlEncMGF1SHA512Url = "http://www.w3.org/2009/xmlenc11#mgf1sha512";

        // Symmetric Key Wrap
        public const string XmlEncAES128KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
        public const string XmlEncAES192KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
        public const string XmlEncAES256KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
    }
}
