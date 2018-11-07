using System;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    [Serializable]
    public class InvalidSignatureException : Exception
    {
        public InvalidSignatureException() { }
        public InvalidSignatureException(string message) : base(message) { }
        public InvalidSignatureException(string message, Exception inner) : base(message, inner) { }
        protected InvalidSignatureException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
