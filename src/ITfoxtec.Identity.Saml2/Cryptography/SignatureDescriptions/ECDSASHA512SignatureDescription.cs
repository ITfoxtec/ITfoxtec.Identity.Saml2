#if NET && !NET70 && !NET60
namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public sealed class ECDSASHA512SignatureDescription : ECDSASignatureDescription
    {
        public ECDSASHA512SignatureDescription() : base("SHA512")
        { }
    }
}
#endif
