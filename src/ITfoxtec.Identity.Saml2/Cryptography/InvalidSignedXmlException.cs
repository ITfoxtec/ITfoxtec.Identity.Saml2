using System;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    [Serializable]
    public class InvalidSignedXmlException : Exception
    {
        public InvalidSignedXmlException() { }
        public InvalidSignedXmlException(string message) : base(message) { }
        public InvalidSignedXmlException(string message, Exception inner) : base(message, inner) { }
        protected InvalidSignedXmlException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
