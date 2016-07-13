
using System;
namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// Authentication context is defined as the information, additional to the authentication assertion itself, that
    /// the relying party may require before it makes an entitlements decision with respect to an authentication
    /// assertion. Such context may include, but is not limited to, the actual authentication method used (see the
    /// SAML assertions and protocols specification [SAMLCore] for more information).
    /// </summary>
    public static class AuthnContextClassTypes
    {
        /// <summary>
        /// The Internet Protocol class is applicable when a principal is authenticated through the use of a provided IP address.
        /// </summary>
        public static Uri InternetProtocol = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol");

        /// <summary>
        /// The Internet Protocol Password class is applicable when a principal is authenticated through the use of a
        /// provided IP address, in addition to a username/password.
        /// </summary>
        public static Uri InternetProtocolPassword = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword");

        /// <summary>
        /// [Supported by AD FS 2.0]
        /// This class is applicable when the principal has authenticated using a password to a local authentication
        /// authority, in order to acquire a Kerberos ticket. That Kerberos ticket is then used for subsequent network
        /// authentication.
        /// </summary>
        public static Uri Kerberos = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos");

        /// <summary>
        /// [Supported by AD FS 2.0]
        /// </summary>
        public static Uri IntegratedWindowsAuthentication = new Uri("urn:federation:authentication:windows");

        /// <summary>
        /// Reflects no mobile customer registration procedures and an authentication of the mobile device without
        /// requiring explicit end-user interaction. This context class authenticates only the device and never the user;
        /// it is useful when services other than the mobile operator want to add a secure device authentication to
        /// their authentication process.
        /// </summary>
        public static Uri MobileOneFactorUnregistered = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered");

        /// <summary>
        /// Reflects no mobile customer registration procedures and a two-factor based authentication, such as
        /// secure device and user PIN. This context class is useful when a service other than the mobile operator
        /// wants to link their customer ID to a mobile supplied two-factor authentication service by capturing mobile
        /// phone data at enrollment.
        /// </summary>
        public static Uri MobileTwoFactorUnregistered = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered");

        /// <summary>
        /// Reflects mobile contract customer registration procedures and a single factor authentication. For example,
        /// a digital signing device with tamper resistant memory for key storage, such as the mobile MSISDN, but no
        /// required PIN or biometric for real-time user authentication.
        /// </summary>
        public static Uri MobileOneFactorContract = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract");

        /// <summary>
        /// Reflects mobile contract customer registration procedures and a two-factor based authentication. For
        /// example, a digital signing device with tamper resistant memory for key storage, such as a GSM SIM, that
        /// requires explicit proof of user identity and intent, such as a PIN or biometric.
        /// </summary>
        public static Uri MobileTwoFactorContract = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract");
    
        /// <summary>
        /// [Supported by AD FS 2.0]
        /// The Password class is applicable when a principal authenticates to an authentication authority through the
        /// presentation of a password over an unprotected HTTP session.
        /// </summary>
        public static Uri UserNameAndPassword = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

        /// <summary>
        /// [Supported by AD FS 2.0]
        /// The PasswordProtectedTransport class is applicable when a principal authenticates to an authentication
        /// authority through the presentation of a password over a protected session.
        /// </summary>
        public static Uri PasswordProtectedTransport = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        /// <summary>
        /// The Secure Remote Password class is applicable when the authentication was performed by means of
        /// Secure Remote Password as specified in [RFC 2945].
        /// </summary>
        public static Uri SecureRemotePassword = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword");

        /// <summary>
        /// The PreviousSession class is applicable when a principal had authenticated to an authentication authority
        /// at some point in the past using any authentication context supported by that authentication authority.
        /// Consequently, a subsequent authentication event that the authentication authority will assert to the relying
        /// party may be significantly separated in time from the principal's current resource access request.
        /// </summary>
        public static Uri PreviousSession = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession");

        /// <summary>
        /// [Supported by AD FS 2.0]
        /// The X509 context class indicates that the principal authenticated by means of a digital signature where the
        /// key was validated as part of an X.509 Public Key Infrastructure. 
        /// </summary>
        public static Uri X509Certificate = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

        /// <summary>
        /// The PGP context class indicates that the principal authenticated by means of a digital signature where the
        /// key was validated as part of a PGP Public Key Infrastructure. 
        /// </summary>
        public static Uri PublicKeyPgp = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PGP");

        /// <summary>
        /// The SPKI context class indicates that the principal authenticated by means of a digital signature where the
        /// key was validated via an SPKI Infrastructure.
        /// </summary>
        public static Uri PublicKeySpki = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI");

        /// <summary>
        /// This context class indicates that the principal authenticated by means of a digital signature according to
        /// the processing rules specified in the XML Digital Signature specification [XMLSig].
        /// </summary>
        public static Uri PublicKeyXmlDigitalDignature = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig");

        /// <summary>
        /// The Smartcard class is identified when a principal authenticates to an authentication authority using a
        /// smartcard.
        /// </summary>
        public static Uri Smartcard = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard");

        /// <summary>
        /// The SmartcardPKI class is applicable when a principal authenticates to an authentication authority through
        /// a two-factor authentication mechanism using a smartcard with enclosed private key and a PIN.
        /// </summary>
        public static Uri SmartcardPKI = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI");

        /// <summary>
        /// The Software-PKI class is applicable when a principal uses an X.509 certificate stored in software to
        /// authenticate to the authentication authority.
        /// </summary>
        public static Uri SoftwarePki = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI");

        /// <summary>
        /// This class is used to indicate that the principal authenticated via the provision of a fixed-line telephone
        /// number, transported via a telephony protocol such as ADSL.
        /// </summary>
        public static Uri Telephony = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony");

        /// <summary>
        /// Indicates that the principal is "roaming" (perhaps using a phone card) and authenticates via the means of
        /// the line number, a user suffix, and a password element.
        /// </summary>
        public static Uri TelephonyNomad = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony");

        /// <summary>
        /// This class is used to indicate that the principal authenticated via the provision of a fixed-line telephone
        /// number and a user suffix, transported via a telephony protocol such as ADSL. 
        /// </summary>
        public static Uri TelephonyPersonal = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony");

        /// <summary>
        /// Indicates that the principal authenticated via the means of the line number, a user suffix, and a password element.
        /// </summary>
        public static Uri TelephonyAuthenticated = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony");

        /// <summary>
        /// [Supported by AD FS 2.0]
        /// This class indicates that the principal authenticated by means of a client certificate, secured with the
        /// SSL/TLS transport.
        /// </summary>
        public static Uri TransportLayerSecurityClient = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient");

        /// <summary>
        /// The TimeSyncToken class is applicable when a principal authenticates through a time synchronization token.
        /// </summary>
        public static Uri TimeSyncToken = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken");       

        /// <summary>
        /// The Unspecified class indicates that the authentication was performed by unspecified means.
        /// </summary>
        public static Uri Unspecified = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");

    }
}
