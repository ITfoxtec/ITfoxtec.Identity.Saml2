using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Schemas.Conditions
{
    public interface ICondition
    {
        XElement ToXElement();
    }
}