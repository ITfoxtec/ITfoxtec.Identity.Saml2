using ITfoxtec.Identity.Saml2.Cryptography;
using System.Security.Cryptography.Xml;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography;

public class XmlCanonicalizationMethodTests
{
    [Theory]
    [InlineData(SignedXml.XmlDsigExcC14NTransformUrl)]
    [InlineData(SignedXml.XmlDsigExcC14NWithCommentsTransformUrl)]
    public void ValidateCanonicalizationMethod_AcceptsSupportedMethods(string canonicalizationMethod)
    {
        XmlCanonicalizationMethod.ValidateCanonicalizationMethod(canonicalizationMethod);
    }

    [Fact]
    public void ValidateCanonicalizationMethod_RejectsUnsupportedMethod()
    {
        Assert.Throws<NotSupportedException>(() =>
            XmlCanonicalizationMethod.ValidateCanonicalizationMethod(SignedXml.XmlDsigC14NTransformUrl));
    }

    [Fact]
    public void GetTransform_ReturnsExclusiveCanonicalizationTransform()
    {
        var transform = XmlCanonicalizationMethod.GetTransform(SignedXml.XmlDsigExcC14NTransformUrl);

        Assert.IsType<XmlDsigExcC14NTransform>(transform);
        Assert.False(transform is XmlDsigExcC14NWithCommentsTransform);
    }

    [Fact]
    public void GetTransform_ReturnsExclusiveCanonicalizationWithCommentsTransform()
    {
        var transform = XmlCanonicalizationMethod.GetTransform(SignedXml.XmlDsigExcC14NWithCommentsTransformUrl);

        Assert.IsType<XmlDsigExcC14NWithCommentsTransform>(transform);
    }
}
