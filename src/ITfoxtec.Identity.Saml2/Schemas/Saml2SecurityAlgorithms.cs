namespace ITfoxtec.Identity.Saml2.Schemas
{
    public static class Saml2SecurityAlgorithms
    {
        /// <summary>
        /// URI for the SHA-1 digest algorithm.
        /// </summary>
        public const string Sha1Digest = "http://www.w3.org/2000/09/xmldsig#sha1";
        /// <summary>
        /// URI for the RSA-SHA-1 signature method for signing XML.
        /// </summary>
        public const string RsaSha1Signature = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";       

        /// <summary>
        /// URI for the SHA-256 digest algorithm.
        /// </summary>
        public const string Sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256";
        /// <summary>
        /// URI for the RSA-SHA-256 signature method for signing XML.
        /// </summary>
        public const string RsaSha256Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        /// <summary>
        /// URI for the SHA-384 digest algorithm.
        /// </summary>
        public const string Sha384Digest = "http://www.w3.org/2001/04/xmldsig-more#sha384";
        /// <summary>
        /// URI for the RSA-SHA-384 signature method for signing XML.
        /// </summary>
        public const string RsaSha384Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

        /// <summary>
        /// URI for the SHA-512 digest algorithm.
        /// </summary>
        public const string Sha512Digest = "http://www.w3.org/2001/04/xmlenc#sha512";
        /// <summary>
        /// URI for the RSA-SHA-512 signature method for signing XML.
        /// </summary>
        public const string RsaSha512Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    }
}
