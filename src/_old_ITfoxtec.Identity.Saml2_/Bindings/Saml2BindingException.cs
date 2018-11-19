using System;

namespace ITfoxtec.Identity.Saml2
{
    [Serializable]
    public class Saml2BindingException : Exception
    {
        public Saml2BindingException() { }
        public Saml2BindingException(string message) : base(message) { }
        public Saml2BindingException(string message, Exception inner) : base(message, inner) { }
        protected Saml2BindingException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }

}
