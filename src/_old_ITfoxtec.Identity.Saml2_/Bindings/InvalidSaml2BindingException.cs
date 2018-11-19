using System;

namespace ITfoxtec.Identity.Saml2
{
    [Serializable]
    public class InvalidSaml2BindingException : Exception
    {
        public InvalidSaml2BindingException() { }
        public InvalidSaml2BindingException(string message) : base(message) { }
        public InvalidSaml2BindingException(string message, Exception inner) : base(message, inner) { }
        protected InvalidSaml2BindingException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }

}
