#if NET && !NET70 && !NET60
namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public sealed class ECDSASHA384SignatureDescription : ECDSASignatureDescription
    {
        public ECDSASHA384SignatureDescription() : base("SHA384")
        { }
    }
}
#endif
