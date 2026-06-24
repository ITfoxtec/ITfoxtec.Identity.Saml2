using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography;

public class Saml2EncryptedXmlTests
{
    private const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";

    public static IEnumerable<object[]> SupportedEncryptionCombinations()
    {
        var dataEncryptionAlgorithms = new[]
        {
            Saml2EncryptionAlgorithms.XmlEncAES128Url,
            Saml2EncryptionAlgorithms.XmlEncAES192Url,
            Saml2EncryptionAlgorithms.XmlEncAES256Url,
            Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl,
            Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl,
            Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl
        };
        var keyEncryptionAlgorithms = new[]
        {
            Saml2EncryptionAlgorithms.XmlEncRSA15Url,
            Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl,
            Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url
        };

        foreach (var dataEncryptionAlgorithm in dataEncryptionAlgorithms)
        {
            foreach (var keyEncryptionAlgorithm in keyEncryptionAlgorithms)
            {
                yield return new object[] { dataEncryptionAlgorithm, keyEncryptionAlgorithm };
            }
        }
    }

    [Fact]
    public void Saml2Configuration_DefaultsToBackwardCompatibleEncryptionAlgorithms()
    {
        var config = new Saml2Configuration();

        Assert.Equal(Saml2EncryptionAlgorithms.XmlEncAES256Url, config.EncryptionAlgorithm);
        Assert.Equal(Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl, config.KeyEncryptionAlgorithm);
    }

    [Fact]
    public void EncryptAassertion_UsesDefaultDataAndKeyEncryptionAlgorithms()
    {
        using var rsa = RSA.Create(2048);

        var encryptedData = EncryptAssertion(rsa);
        var namespaces = CreateNamespaceManager(encryptedData);

        Assert.Equal(Saml2EncryptionAlgorithms.XmlEncAES256Url, GetAlgorithm(encryptedData, "self::enc:EncryptedData/enc:EncryptionMethod", namespaces));
        Assert.Equal(Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl, GetAlgorithm(encryptedData, "descendant::enc:EncryptedKey/enc:EncryptionMethod", namespaces));
        Assert.Null(encryptedData.SelectSingleNode("descendant::enc:EncryptedKey/enc:EncryptionMethod/ds:DigestMethod", namespaces));
        Assert.Null(encryptedData.SelectSingleNode("descendant::enc:EncryptedKey/enc:EncryptionMethod/xenc11:MGF", namespaces));
    }

    [Fact]
    public void EncryptAassertion_WithRsaOaep11_AddsSha256DigestAndMgf()
    {
        using var rsa = RSA.Create(2048);

        var encryptedData = EncryptAssertion(
            rsa,
            Saml2EncryptionAlgorithms.XmlEncAES256Url,
            Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url);
        var namespaces = CreateNamespaceManager(encryptedData);

        Assert.Equal(Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url, GetAlgorithm(encryptedData, "descendant::enc:EncryptedKey/enc:EncryptionMethod", namespaces));
        Assert.Equal(Saml2SecurityAlgorithms.Sha256Digest, GetAlgorithm(encryptedData, "descendant::enc:EncryptedKey/enc:EncryptionMethod/ds:DigestMethod", namespaces));
        Assert.Equal(Saml2EncryptionAlgorithms.XmlEncMGF1SHA256Url, GetAlgorithm(encryptedData, "descendant::enc:EncryptedKey/enc:EncryptionMethod/xenc11:MGF", namespaces));
    }

    [Theory]
    [MemberData(nameof(SupportedEncryptionCombinations))]
    public void EncryptAassertion_CanDecryptEncryptedData(string encryptionAlgorithm, string keyEncryptionAlgorithm)
    {
        using var rsa = RSA.Create(2048);

        var encryptedData = EncryptAssertion(rsa, encryptionAlgorithm, keyEncryptionAlgorithm);
        var encryptedDocument = CreateEncryptedDocument(encryptedData);

        new Saml2EncryptedXml(encryptedDocument, rsa).DecryptDocument();

        var assertion = encryptedDocument.DocumentElement?["Assertion", AssertionNamespace];
        Assert.NotNull(assertion);
        Assert.Equal("https://issuer.example.com", assertion!["Issuer", AssertionNamespace]?.InnerText);
        Assert.Equal("subject@example.com", assertion["Subject", AssertionNamespace]?["NameID", AssertionNamespace]?.InnerText);
    }

    [Fact]
    public void DecryptDocument_RejectsUnsupportedRsaOaepMgfMethod()
    {
        using var rsa = RSA.Create(2048);

        var encryptedData = EncryptAssertion(
            rsa,
            Saml2EncryptionAlgorithms.XmlEncAES256Url,
            Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url);
        var namespaces = CreateNamespaceManager(encryptedData);
        var mgfElement = encryptedData.SelectSingleNode("descendant::enc:EncryptedKey/enc:EncryptionMethod/xenc11:MGF", namespaces) as XmlElement;
        Assert.NotNull(mgfElement);
        mgfElement!.SetAttribute("Algorithm", Saml2EncryptionAlgorithms.XmlEncMGF1SHA1Url);
        var encryptedDocument = CreateEncryptedDocument(encryptedData);

        var exception = Assert.Throws<NotSupportedException>(() => new Saml2EncryptedXml(encryptedDocument, rsa).DecryptDocument());

        Assert.Contains("Unsupported RSA-OAEP MGF method", exception.Message);
    }

    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128KeyWrapUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES192KeyWrapUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256KeyWrapUrl)]
    public void EncryptAassertion_RejectsKeyWrapAlgorithmsAsDataEncryption(string encryptionAlgorithm)
    {
        using var rsa = RSA.Create(2048);

        var exception = Assert.Throws<NotSupportedException>(() => EncryptAssertion(rsa, encryptionAlgorithm));

        Assert.Contains("Unsupported data encryption algorithm", exception.Message);
    }

    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256KeyWrapUrl)]
    public void EncryptAassertion_RejectsNonKeyTransportAlgorithmsAsKeyEncryption(string keyEncryptionAlgorithm)
    {
        using var rsa = RSA.Create(2048);

        var exception = Assert.Throws<NotSupportedException>(() =>
            EncryptAssertion(rsa, Saml2EncryptionAlgorithms.XmlEncAES256Url, keyEncryptionAlgorithm));

        Assert.Contains("Unsupported key encryption algorithm", exception.Message);
    }

    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES192Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES128GCMUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES192GCMUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncAES256GCMUrl)]
    public void EncryptAassertion_EmitsConfiguredDataEncryptionAlgorithm(string encryptionAlgorithm)
    {
        using var rsa = RSA.Create(2048);

        var encryptedData = EncryptAssertion(rsa, encryptionAlgorithm);
        var namespaces = CreateNamespaceManager(encryptedData);

        Assert.Equal(encryptionAlgorithm, GetAlgorithm(encryptedData, "self::enc:EncryptedData/enc:EncryptionMethod", namespaces));
    }

    [Theory]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncRSA15Url)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl)]
    [InlineData(Saml2EncryptionAlgorithms.XmlEncRSAOAEP11Url)]
    public void EncryptAassertion_EmitsConfiguredKeyEncryptionAlgorithm(string keyEncryptionAlgorithm)
    {
        using var rsa = RSA.Create(2048);

        var encryptedData = EncryptAssertion(rsa, Saml2EncryptionAlgorithms.XmlEncAES256Url, keyEncryptionAlgorithm);
        var namespaces = CreateNamespaceManager(encryptedData);

        Assert.Equal(keyEncryptionAlgorithm, GetAlgorithm(encryptedData, "descendant::enc:EncryptedKey/enc:EncryptionMethod", namespaces));
    }

    private static XmlElement EncryptAssertion(
        RSA rsa,
        string encryptionAlgorithm = Saml2EncryptionAlgorithms.XmlEncAES256Url,
        string keyEncryptionAlgorithm = Saml2EncryptionAlgorithms.XmlEncRSAOAEPUrl)
    {
        var assertionDocument = CreateAssertionDocument();
        return new Saml2EncryptedXml(rsa).EncryptAassertion(assertionDocument.DocumentElement!, encryptionAlgorithm, keyEncryptionAlgorithm);
    }

    private static XmlDocument CreateAssertionDocument()
    {
        var assertionDocument = new XmlDocument
        {
            PreserveWhitespace = true
        };
        assertionDocument.LoadXml(
            """
            <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion">
              <saml:Issuer>https://issuer.example.com</saml:Issuer>
              <saml:Subject>
                <saml:NameID>subject@example.com</saml:NameID>
              </saml:Subject>
            </saml:Assertion>
            """);
        return assertionDocument;
    }

    private static XmlDocument CreateEncryptedDocument(XmlElement encryptedData)
    {
        var encryptedDocument = new XmlDocument
        {
            PreserveWhitespace = true
        };
        encryptedDocument.LoadXml("<Root />");
        encryptedDocument.DocumentElement!.AppendChild(encryptedDocument.ImportNode(encryptedData, true));
        return encryptedDocument;
    }

    private static XmlNamespaceManager CreateNamespaceManager(XmlElement element)
    {
        var namespaces = new XmlNamespaceManager(element.OwnerDocument.NameTable);
        namespaces.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);
        namespaces.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        namespaces.AddNamespace("xenc11", "http://www.w3.org/2009/xmlenc11#");
        return namespaces;
    }

    private static string GetAlgorithm(XmlElement element, string xpath, XmlNamespaceManager namespaces)
    {
        var node = element.SelectSingleNode(xpath, namespaces) as XmlElement;
        Assert.NotNull(node);
        return node!.GetAttribute("Algorithm");
    }
}
