using System;

namespace ITfoxtec.Identity.Saml2
{
    [Serializable]
    public class Saml2RequestException : Exception
    {
        public Saml2RequestException() { }
        public Saml2RequestException(string message) : base(message) { }
        public Saml2RequestException(string message, Exception inner) : base(message, inner) { }
        protected Saml2RequestException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
