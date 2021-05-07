namespace TestWebAppCoreNemLogin3Sp.Identity
{
    public static class OioSaml3ClaimTypes
    {
        /// <summary>
        /// Specifies the version of the OIOSAML profile specification - the current version is shown in example below.
        /// </summary>
        public const string SpecVersion = "https://data.gov.dk/model/core/specVersion";
        /// <summary>
        /// Contains a base64-encoded bootstrap token for identity-based web services(see[OIO IDWS] specifications).
        /// </summary>
        public const string BootstrapToken = "https://data.gov.dk/model/core/eid/bootstrapToken";
        /// <summary>
        /// Contains a base64-encoded value describing privileges assigned to the identity 
        /// (see OIO Basic Privilege Profile specification [OIOBPP] for details).
        /// </summary>
        public const string PrivilegesIntermediate = "https://data.gov.dk/model/core/eid/privilegesIntermediate";
        /// <summary>
        /// Contains the overall level of assurance of the authentication as defined by the Danish [NSIS] standard. 
        /// The allowed values are ‘Low’, ‘Substantial’ and ‘High’
        /// </summary>
        public const string NsisLoa = "https://data.gov.dk/concept/core/nsis/loa";
        /// <summary>
        /// Contains Identity Assurance Level (IAL) as defined by the Danish [NSIS] standard.
        /// The allowed values are ‘Low’, ‘Substantial’ and ‘High’.
        /// </summary>
        public const string NsisIal = "https://data.gov.dk/concept/core/nsis/ial";
        /// <summary>
        /// Contains Authenticator Assurance Level (AAL) as defined by the Danish[NSIS] standard.
        /// The allowed values are ‘Low’, ‘Substantial’ and ‘High’.
        /// </summary>
        public const string NsisAal = "https://data.gov.dk/concept/core/nsis/aal";
        /// <summary>
        /// Contains the full name.
        /// </summary>
        public const string FullName = "https://data.gov.dk/model/core/eid/fullName";
        /// <summary>
        /// Contains the first name(s). In case the person has multiple first names, one or more of these MUST be present.
        /// Middlenames are not allowed.
        /// </summary>
        public const string FirstName = "https://data.gov.dk/model/core/eid/firstName";
        /// <summary>
        /// Contains the last name.
        /// </summary>
        public const string LastName = "https://data.gov.dk/model/core/eid/lastName";
        /// <summary>
        /// Contains an alias of the identity. This attribute can be used as a display name selected by the user 
        /// as an alternative to the above name attributes.
        /// </summary>
        public const string Alias = "https://data.gov.dk/model/core/eid/alias";
        /// <summary>
        /// Contains the email address of the identity. In cases there are multiple addresses known this attribute can 
        /// be multi-valued(i.e. using multiple <AttributeValue> elements).
        /// </summary>
        public const string Email = "https://data.gov.dk/model/core/eid/email";
        /// <summary>
        /// Contains the Danish CPR number for the identity represented by 10 digits.
        /// </summary>
        public const string CprNumber = "https://data.gov.dk/model/core/eid/cprNumber";
        /// <summary>
        /// Contains the age of the person represented by an integer.
        /// </summary>
        public const string Age = "https://data.gov.dk/model/core/eid/age";
        /// <summary>
        /// Contains the central UUID for the person defined by the Danish Civil Registration Authority.
        /// This identifier is expected to replace the 10-digit CPR number.
        /// </summary>
        public const string CprUuid = "https://data.gov.dk/model/core/eid/cprUuid";
        /// <summary>
        /// Contains the date of birth.
        /// </summary>
        public const string DateOfBirth = "https://data.gov.dk/model/core/eid/dateOfBirth";
        /// <summary>
        /// Contains the legacy PID number used in OCES infrastructure. Note: this attribute is deprecated and 
        /// SPs MUST make plans for phasing out any dependencies on this.
        /// </summary>
        public const string PersonPid = "https://data.gov.dk/model/core/eid/person/pid";
        /// <summary>
        /// Contains a UUID for the professional identity which is shared across all public sector SPs. The identifier is 
        /// specific to the professional role and is not related to the associated natural person. The UUID MUST follow RFC 4122. 
        /// This attribute is the successor to the RID attribute (see below) but is globally unique.
        /// </summary>
        public const string ProfessionalUuidPersistent = "https://data.gov.dk/model/core/eid/professional/uuid/persistent";
        /// <summary>
        /// Contains the legacy RID number used in OCES infrastructure. Note: this attribute is deprecated and SPs MUST make 
        /// plans for phasing out any dependencies on this.
        /// </summary>
        public const string ProfessionalRid = "https://data.gov.dk/model/core/eid/professional/rid";
        /// <summary>
        /// Contains the CVR number (8 digits) of the organization related to the authentication context.Note that a professional
        /// may be associated with several organizations but only one organization is allowed per authentication context.
        /// </summary>
        public const string ProfessionalCvr = "https://data.gov.dk/model/core/eid/professional/cvr";
        /// <summary>
        /// Contains the name of the organization related to the authentication context. Note that a professional may be 
        /// associated with several organizations but only one organization is allowed per authentication context.
        /// </summary>
        public const string ProfessionalOrgName = "https://data.gov.dk/model/core/eid/professional/orgName";
        /// <summary>
        /// Contains the Production Unit identifier (10 digits) which the professional is associated to within the organization 
        /// related to the authentication context. 
        /// </summary>
        public const string ProfessionalProductionUnit = "https://data.gov.dk/model/core/eid/professional/productionUnit";
        /// <summary>
        /// Contains the SE number identifier (8 digits) which the professional is associated to within the organization related 
        /// to the authentication context.
        /// </summary>
        public const string ProfessionalSeNumber = "https://data.gov.dk/model/core/eid/professional/seNumber";
        /// <summary>
        /// Contains the CVR number(s) of an organization, if the professional is allowed to fully represent the organization with 
        /// respect to public sector services.In other words, the professional has a strong legal binding to the organizations – 
        /// the type of binding will depend on type of organization. If more organizations can be fully represented the IdP MAY 
        /// include multiple <AttributeValue> elements.
        /// </summary>
        public const string ProfessionalAuthorizedToRepresent = "https://data.gov.dk/model/core/eid/professional/authorizedToRepresent";
    }
}
