using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Conditions
{
    public abstract class ConditionAbstract
    {
        public abstract XElement ToXElement();
    }
}