using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// The message sender MAY use the Reason attribute to indicate the reason for sending the
    /// <LogoutRequest>. The following values are defined by this specification for use by all message
    /// senders; other values MAY be agreed on between participants.
    /// </summary>
    public static class ProcessingRules
    {
        /// <summary>
        /// Specifies that the message is being sent because the principal wishes to terminate the indicated session.
        /// </summary>
        public static Uri User = new Uri("urn:oasis:names:tc:SAML:2.0:logout:user");

        /// <summary>
        /// Specifies that the message is being sent because an administrator wishes to terminate the indicated session for that principal.
        /// </summary>
        public static Uri Admin = new Uri("urn:oasis:names:tc:SAML:2.0:logout:admin");
    }
}
