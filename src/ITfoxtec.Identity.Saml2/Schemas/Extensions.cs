using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas
{
    /// <summary>
    /// This extension point contains optional protocol message extension elements that are agreed on between 
    /// the communicating parties.
    /// </summary>
    public class Extensions
    {
        const string elementName = Saml2Constants.Message.Extensions;

        /// <summary>
        /// [Optional] 
        /// Extension data added as text insight the Extensions element.
        /// </summary>
        public string Data { get; set; } 

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(Data);

            return envelope;
        }
    }
}
