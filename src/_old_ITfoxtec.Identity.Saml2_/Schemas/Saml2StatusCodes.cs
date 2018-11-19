
namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// Status codes, mapped against states in section 3.2.2.2 in the SAML2 spec.
    /// </summary>
    public enum Saml2StatusCodes
    {
        /// <summary>
        /// The request succeeded.
        /// </summary>
        Success,
        /// <summary>
        /// The request could not be performed due to an error on the part of the requester.
        /// </summary>
        Requester,
        /// <summary>
        /// The request could not be performed due to an error on the part of the SAML responder or SAML authority.
        /// </summary>
        Responder,
        /// <summary>
        /// The SAML responder could not process the request because the version of the request message was incorrect.
        /// </summary>
        VersionMismatch,
        /// <summary>
        /// The responding provider was unable to successfully authenticate the principal.
        /// </summary>
        AuthnFailed,
        /// <summary>
        /// Unexpected or invalid content was encountered within a &lt;saml:Attribute&gt; or &lt;saml:AttributeValue&gt; element.
        /// </summary>
        InvalidAttrNameOrValue,
        /// <summary>
        /// The responding provider cannot or will not support the requested name identifier policy.
        /// </summary>
        InvalidNameIdPolicy,
        /// <summary>
        /// The specified authentication context requirements cannot be met by the responder.
        /// </summary>
        NoAuthnContext,
        /// <summary>
        /// Used by an intermediary to indicate that none of the supported identity provider &lt;Loc&gt; elements in an
        /// &lt;IDPList&gt; can be resolved or that none of the supported identity providers are available.
        /// </summary>
        NoAvailableIDP,
        /// <summary>
        /// Indicates the responding provider cannot authenticate the principal passively, as has been requested.
        /// </summary>
        NoPassive,
        /// <summary>
        /// Used by an intermediary to indicate that none of the identity providers in an &lt;IDPList&gt; are
        /// supported by the intermediary.
        /// </summary>
        NoSupportedIDP,
        /// <summary>
        /// Used by a session authority to indicate to a session participant that it was not able to propagate logout
        /// to all other session participants.
        /// </summary>
        PartialLogout,
        /// <summary>
        /// Indicates that a responding provider cannot authenticate the principal directly and is not permitted to
        /// proxy the request further.
        /// </summary>
        ProxyCountExceeded,
        /// <summary>
        /// The SAML responder or SAML authority is able to process the request but has chosen not to respond.
        /// This status code MAY be used when there is concern about the security context of the request
        /// message or the sequence of request messages received from a particular requester.
        /// </summary>
        RequestDenied,
        /// <summary>
        /// The SAML responder or SAML authority does not support the request.
        /// </summary>
        RequestUnsupported,
        /// <summary>
        /// The SAML responder cannot process any requests with the protocol version specified in the request.
        /// </summary>
        RequestVersionDeprecated,
        /// <summary>
        /// The SAML responder cannot process the request because the protocol version specified in the
        /// request message is a major upgrade from the highest protocol version supported by the responder.
        /// </summary>
        RequestVersionTooHigh,
        /// <summary>
        /// The SAML responder cannot process the request because the protocol version specified in the
        /// request message is too low.
        /// </summary>
        RequestVersionTooLow,
        /// <summary>
        /// The resource value provided in the request message is invalid or unrecognized.
        /// </summary>
        ResourceNotRecognized,
        /// <summary>
        /// The response message would contain more elements than the SAML responder is able to return.
        /// </summary>
        TooManyResponses,
        /// <summary>
        /// An entity that has no knowledge of a particular attribute profile has been presented with an attribute
        /// drawn from that profile.
        /// </summary>
        UnknownAttrProfile,
        /// <summary>
        /// The responding provider does not recognize the principal specified or implied by the request.
        /// </summary>
        UnknownPrincipal,
        /// <summary>
        /// The SAML responder cannot properly fulfill the request using the protocol binding specified in the
        /// request.
        /// </summary>
        UnsupportedBinding,
    }
}
