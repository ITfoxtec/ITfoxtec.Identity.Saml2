using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography;

public class EncryptionAlgorithmTests
{
    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES192Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl)]
    public void ValidateDataEncryptionAlgorithm_AcceptsSupportedDataEncryptionAlgorithms(string encryptionAlgorithm)
    {
        EncryptionAlgorithm.ValidateDataEncryptionAlgorithm(encryptionAlgorithm);
    }

    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncRSA15Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url)]
    public void ValidateKeyEncryptionAlgorithm_AcceptsSupportedKeyTransportAlgorithms(string keyEncryptionAlgorithm)
    {
        EncryptionAlgorithm.ValidateKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
    }

    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128KeyWrapUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES192KeyWrapUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256KeyWrapUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl)]
    public void ValidateDataEncryptionAlgorithm_RejectsNonDataEncryptionAlgorithms(string encryptionAlgorithm)
    {
        var exception = Assert.Throws<NotSupportedException>(() =>
            EncryptionAlgorithm.ValidateDataEncryptionAlgorithm(encryptionAlgorithm));

        Assert.Contains("Unsupported data encryption algorithm", exception.Message);
    }

    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256KeyWrapUrl)]
    public void ValidateKeyEncryptionAlgorithm_RejectsNonKeyTransportAlgorithms(string keyEncryptionAlgorithm)
    {
        var exception = Assert.Throws<NotSupportedException>(() =>
            EncryptionAlgorithm.ValidateKeyEncryptionAlgorithm(keyEncryptionAlgorithm));

        Assert.Contains("Unsupported key encryption algorithm", exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateDataEncryptionAlgorithm_RejectsEmptyAlgorithm(string? encryptionAlgorithm)
    {
        Assert.Throws<ArgumentNullException>(() =>
            EncryptionAlgorithm.ValidateDataEncryptionAlgorithm(encryptionAlgorithm!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateKeyEncryptionAlgorithm_RejectsEmptyAlgorithm(string? keyEncryptionAlgorithm)
    {
        Assert.Throws<ArgumentNullException>(() =>
            EncryptionAlgorithm.ValidateKeyEncryptionAlgorithm(keyEncryptionAlgorithm!));
    }
}
