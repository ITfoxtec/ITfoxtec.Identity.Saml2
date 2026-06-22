#if NET && !NET70 && !NET60
namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public sealed class ECDSASHA256SignatureDescription : ECDSASignatureDescription
    {
        public ECDSASHA256SignatureDescription() : base("SHA256")
        { }
    }
}
#endif
