namespace TestWebAppCoreNemLogin3Sp.Identity
{
    public static class OioSaml2ClaimTypes
    {
        /// <summary>
        /// AssuranceLevel
        /// https://www.digitaliser.dk/news/6072243
        /// To support the cases where authentications does not yield a NSIS Level of Assurance the NemLog-in IdP will instead provide 
        /// the old OIO SAML 2 AssuranceLevel attribute in the produced SAML Assertion. 
        /// </summary>
        public const string AssuranceLevel = "dk:gov:saml:attribute:AssuranceLevel";
    }
}
