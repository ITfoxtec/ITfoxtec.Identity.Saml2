using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace ITfoxtec.Identity.Saml2.Tests.Tokens
{
    public class Saml2ResponseSecurityTokenHandlerTests
    {
        [Theory]
        [InlineData("AuthnContextClassRef")]
        [InlineData("AuthnContextDeclRef")]
        public void ReadSaml2Token_AcceptsAuthenticationContextReferences(string referenceElement)
        {
            var handler = CreateHandler();
            var assertion = CreateAssertion($"""
                <AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">
                    <AuthnContext>
                        <{referenceElement}>urn:test:authentication</{referenceElement}>
                    </AuthnContext>
                </AuthnStatement>
                """);

            var token = handler.ReadSaml2Token(assertion);

            var statement = Assert.IsType<Saml2AuthenticationStatement>(Assert.Single(token.Assertion.Statements));
            var context = statement.AuthenticationContext;
            if (referenceElement == "AuthnContextClassRef")
            {
                Assert.Equal("urn:test:authentication", context.ClassReference.OriginalString);
            }
            else
            {
                Assert.Null(context.ClassReference);
                Assert.Equal("urn:test:authentication", context.DeclarationReference.OriginalString);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData("<AssertionIDRef>_evidence</AssertionIDRef>")]
        public async Task ReadSaml2Token_RejectsUnexpectedEvidenceWithoutHanging(string precedingEvidence)
        {
            var handler = CreateHandler();
            var assertion = CreateAssertion($"""
                <AuthzDecisionStatement Resource="urn:test:resource" Decision="Permit">
                    <Action Namespace="urn:oasis:names:tc:SAML:1.0:action:rwedc">Read</Action>
                    <Evidence>{precedingEvidence}<Unexpected xmlns="urn:test:unexpected" /></Evidence>
                </AuthzDecisionStatement>
                """);

            // Bound the test even if a dependency regression causes the parser to loop forever.
            var exception = await Task.Run(() => Record.Exception(() => handler.ReadSaml2Token(assertion)))
                .WaitAsync(TimeSpan.FromSeconds(5));

            Assert.IsType<Saml2SecurityTokenReadException>(exception);
        }

        [Fact]
        public void ReadSaml2Token_AcceptsOrdinaryNestedAssertions()
        {
            var handler = CreateHandler();

            var token = handler.ReadSaml2Token(CreateNestedAssertions(3));

            var child = Assert.Single(token.Assertion.Advice.Assertions);
            Assert.Single(child.Advice.Assertions);
        }

        [Fact]
        public void ReadSaml2Token_RejectsExcessiveNestingAndCanReadTheNextToken()
        {
            var handler = CreateHandler();

            var exception = Assert.Throws<Saml2SecurityTokenReadException>(() =>
                handler.ReadSaml2Token(CreateNestedAssertions(10)));

            Assert.Contains("IDX13111", exception.Message);
            var token = handler.ReadSaml2Token(CreateAssertion());
            Assert.Equal("user@example.test", token.Assertion.Subject.NameId.Value);
        }

        private static Saml2ResponseSecurityTokenHandler CreateHandler()
        {
            return Saml2ResponseSecurityTokenHandler.GetSaml2SecurityTokenHandler(new Saml2IdentityConfiguration());
        }

        private static string CreateNestedAssertions(int depth)
        {
            var assertion = CreateAssertion();
            for (var level = 1; level < depth; level++)
            {
                assertion = CreateAssertion($"<Advice>{assertion}</Advice>");
            }
            return assertion;
        }

        private static string CreateAssertion(string content = "")
        {
            return $"""
                <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="_test" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
                    <Issuer>https://idp.example.test</Issuer>
                    <Subject><NameID>user@example.test</NameID></Subject>
                    {content}
                </Assertion>
                """;
        }
    }
}
