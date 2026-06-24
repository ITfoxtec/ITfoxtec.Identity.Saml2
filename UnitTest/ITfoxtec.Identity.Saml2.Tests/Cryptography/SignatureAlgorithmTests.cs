using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography;

public class SignatureAlgorithmTests
{
    public static IEnumerable<object[]> SupportedSignatureAlgorithms()
    {
        yield return new object[] { Saml2SecurityAlgorithms.RsaSha1Signature, Saml2SecurityAlgorithms.Sha1Digest };
        yield return new object[] { Saml2SecurityAlgorithms.RsaSha256Signature, Saml2SecurityAlgorithms.Sha256Digest };
        yield return new object[] { Saml2SecurityAlgorithms.RsaSha384Signature, Saml2SecurityAlgorithms.Sha384Digest };
        yield return new object[] { Saml2SecurityAlgorithms.RsaSha512Signature, Saml2SecurityAlgorithms.Sha512Digest };
        yield return new object[] { Saml2SecurityAlgorithms.RsaPssSha256Signature, Saml2SecurityAlgorithms.Sha256Digest };
        yield return new object[] { Saml2SecurityAlgorithms.EcdsaSha256Signature, Saml2SecurityAlgorithms.Sha256Digest };
        yield return new object[] { Saml2SecurityAlgorithms.EcdsaSha384Signature, Saml2SecurityAlgorithms.Sha384Digest };
        yield return new object[] { Saml2SecurityAlgorithms.EcdsaSha512Signature, Saml2SecurityAlgorithms.Sha512Digest };
    }

    [Theory]
    [MemberData(nameof(SupportedSignatureAlgorithms))]
    public void ValidateAlgorithm_AcceptsSupportedSignatureAlgorithms(string signatureAlgorithm, string _)
    {
        SignatureAlgorithm.ValidateAlgorithm(signatureAlgorithm);
    }

    [Theory]
    [MemberData(nameof(SupportedSignatureAlgorithms))]
    public void DigestMethod_ReturnsDigestForSignatureAlgorithm(string signatureAlgorithm, string expectedDigestMethod)
    {
        Assert.Equal(expectedDigestMethod, SignatureAlgorithm.DigestMethod(signatureAlgorithm));
    }

    [Fact]
    public void ValidateAlgorithm_RejectsUnsupportedSignatureAlgorithm()
    {
        Assert.Throws<NotSupportedException>(() =>
            SignatureAlgorithm.ValidateAlgorithm("urn:unsupported:signature"));
    }

    [Fact]
    public void DigestMethod_RejectsUnsupportedSignatureAlgorithm()
    {
        Assert.Throws<NotSupportedException>(() =>
            SignatureAlgorithm.DigestMethod("urn:unsupported:signature"));
    }
}
