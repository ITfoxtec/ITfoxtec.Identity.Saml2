using System.Xml;

namespace ITfoxtec.Identity.Saml2.Tests.Request;

public class Saml2AuthnResponseSubjectConfirmationExpirationTests
{
    // Exposes the protected expiration validation without needing a full (signed) SAML response.
    private class TestSaml2AuthnResponse : Saml2AuthnResponse
    {
        public TestSaml2AuthnResponse(Saml2Configuration config) : base(config) { }

        public void ValidateExpiration(XmlElement subjectElement) => ValidateSubjectConfirmationExpiration(subjectElement);
    }

    private static XmlElement CreateSubjectElement(DateTimeOffset? notBefore, DateTimeOffset? notOnOrAfter)
    {
        var attributes = "";
        if (notBefore.HasValue)
        {
            attributes += $@" NotBefore=""{notBefore.Value.UtcDateTime:o}""";
        }
        if (notOnOrAfter.HasValue)
        {
            attributes += $@" NotOnOrAfter=""{notOnOrAfter.Value.UtcDateTime:o}""";
        }

        var xml = $@"<Subject xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <SubjectConfirmation>
    <SubjectConfirmationData{attributes} />
  </SubjectConfirmation>
</Subject>";

        var document = new XmlDocument();
        document.LoadXml(xml);
        return document.DocumentElement!;
    }

    [Fact]
    public void ValidateExpiration_MissingNotOnOrAfter_Throws()
    {
        var response = new TestSaml2AuthnResponse(new Saml2Configuration());

        var exception = Assert.Throws<Saml2RequestException>(() =>
            response.ValidateExpiration(CreateSubjectElement(notBefore: null, notOnOrAfter: null)));
        Assert.Contains("NotOnOrAfter", exception.Message);
    }

    [Fact]
    public void ValidateExpiration_NotBeforeWithinClockSkew_DoesNotThrow()
    {
        var config = new Saml2Configuration { ClockSkew = TimeSpan.FromMinutes(5) };
        var response = new TestSaml2AuthnResponse(config);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(3);
        var notOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(5);

        response.ValidateExpiration(CreateSubjectElement(notBefore, notOnOrAfter));
    }

    [Fact]
    public void ValidateExpiration_NotBeforeBeyondClockSkew_Throws()
    {
        var config = new Saml2Configuration { ClockSkew = TimeSpan.FromMinutes(5) };
        var response = new TestSaml2AuthnResponse(config);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(8);
        var notOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(20);

        var exception = Assert.Throws<Saml2RequestException>(() =>
            response.ValidateExpiration(CreateSubjectElement(notBefore, notOnOrAfter)));
        Assert.Contains("not valid yet", exception.Message);
    }

    [Fact]
    public void ValidateExpiration_NotOnOrAfterWithinClockSkew_DoesNotThrow()
    {
        var config = new Saml2Configuration { ClockSkew = TimeSpan.FromMinutes(5) };
        var response = new TestSaml2AuthnResponse(config);
        var notOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(-3);

        response.ValidateExpiration(CreateSubjectElement(notBefore: null, notOnOrAfter));
    }

    [Fact]
    public void ValidateExpiration_NotOnOrAfterBeyondClockSkew_Throws()
    {
        var config = new Saml2Configuration { ClockSkew = TimeSpan.FromMinutes(5) };
        var response = new TestSaml2AuthnResponse(config);
        var notOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(-8);

        var exception = Assert.Throws<Saml2RequestException>(() =>
            response.ValidateExpiration(CreateSubjectElement(notBefore: null, notOnOrAfter)));
        Assert.Contains("expired", exception.Message);
    }

    [Fact]
    public void ValidateExpiration_NotBeforeAndNotOnOrAfterWithinValidWindow_DoesNotThrow()
    {
        var config = new Saml2Configuration { ClockSkew = TimeSpan.FromMinutes(5) };
        var response = new TestSaml2AuthnResponse(config);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-3);
        var notOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(3);

        response.ValidateExpiration(CreateSubjectElement(notBefore, notOnOrAfter));
    }

    [Fact]
    public void ValidateExpiration_NotBeforeAndNotOnOrAfterBothBeyondClockSkew_ThrowsForNotBefore()
    {
        var config = new Saml2Configuration { ClockSkew = TimeSpan.FromMinutes(5) };
        var response = new TestSaml2AuthnResponse(config);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(8);
        var notOnOrAfter = DateTimeOffset.UtcNow.AddMinutes(20);

        var exception = Assert.Throws<Saml2RequestException>(() =>
            response.ValidateExpiration(CreateSubjectElement(notBefore, notOnOrAfter)));
        Assert.Contains("not valid yet", exception.Message);
    }
}
