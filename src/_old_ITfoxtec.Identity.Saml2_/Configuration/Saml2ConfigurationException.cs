using System;

namespace ITfoxtec.Identity.Saml2.Configuration
{
    [Serializable]
    public class Saml2ConfigurationException : Exception
    {
        public Saml2ConfigurationException() { }
        public Saml2ConfigurationException(string message) : base(message) { }
        public Saml2ConfigurationException(string message, Exception inner) : base(message, inner) { }
        protected Saml2ConfigurationException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
