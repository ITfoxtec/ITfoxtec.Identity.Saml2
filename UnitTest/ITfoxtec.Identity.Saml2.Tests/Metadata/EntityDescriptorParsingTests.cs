using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Identity.Saml2.Tests.Metadata
{
    public class EntityDescriptorParsingTests
    {
        private static readonly XNamespace Md = Saml2MetadataConstants.MetadataNamespaceX;
        private static readonly XNamespace Extension = "urn:test:extension";
        private static readonly XNamespace Ds = SignedXml.XmlDsigNamespaceUrl;

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void ReadAggregate_PreservesDocumentOrderWithinTheMetadataHierarchy(bool idp)
        {
            var group = new XElement(Md + "EntitiesDescriptor",
                new XElement(Md + "Extensions", Entity("hidden")),
                new XElement(Extension + "EntitiesDescriptor", Entity("foreign")),
                new XElement(Md + "EntitiesDescriptor", Entity("first")),
                Entity("second"));
            var reader = new EntityDescriptor();
            Read(reader, group, idp);
            Assert.Equal("first", reader.EntityId);

            group.Elements(Md + "EntitiesDescriptor").Remove();
            Read(reader, group, idp);
            Assert.Equal("second", reader.EntityId);

            group.Elements(Md + "EntityDescriptor").Remove();
            Assert.Throws<Saml2RequestException>(() => Read(reader, group, idp));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void ReadSingleEntity_RequiresMetadataRoot(bool idp)
        {
            var reader = new EntityDescriptor();
            var entity = Entity("partner");
            Read(reader, entity, idp);
            Assert.Equal("partner", reader.EntityId);
            Assert.Throws<Saml2RequestException>(() => Read(reader, new XElement(Extension + "Wrapper", entity), idp));
            Assert.Throws<Saml2RequestException>(() => Read(reader, new XElement(Extension + "EntityDescriptor", entity.Attributes()), idp));
        }

        [Fact]
        public void ReadingBothRoles_PreservesRolesOnlyForTheCurrentEntity()
        {
            var both = Entity("first", new XElement(Md + "IDPSSODescriptor"), new XElement(Md + "SPSSODescriptor"));
            var reader = new EntityDescriptor();
            Read(reader, both, true);
            Read(reader, both, false);
            Assert.NotNull(reader.IdPSsoDescriptor);
            Assert.NotNull(reader.SPSsoDescriptor);

            Read(reader, Entity("second"), false);
            Assert.Equal("second", reader.EntityId);
            Assert.Null(reader.IdPSsoDescriptor);
            Assert.Null(reader.SPSsoDescriptor);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void ReadRole_SelectsOnlyDirectMetadataEndpointsAndNameIdFormats(bool idp)
        {
            var role = new XElement(Md + (idp ? "IDPSSODescriptor" : "SPSSODescriptor"));
            foreach (var name in new[] { idp ? "SingleSignOnService" : "AssertionConsumerService", "SingleLogoutService", "ArtifactResolutionService" })
            {
                XElement Endpoint(XNamespace ns) => new XElement(ns + name, new XAttribute("Binding", "urn:test:binding"),
                    new XAttribute("Location", "https://partner.example.test/" + name), new XAttribute("index", "0"));
                role.Add(Endpoint(Extension), new XElement(Md + "Extensions", Endpoint(Md)), Endpoint(Md));
            }
            role.Add(new XElement(Extension + "NameIDFormat", "urn:test:foreign"), new XElement(Md + "NameIDFormat", "urn:test:format"));
            var reader = new EntityDescriptor();
            Read(reader, Entity("partner", role), idp);

            SsoDescriptorType sso;
            if (idp)
            {
                sso = reader.IdPSsoDescriptor;
                Assert.Equal("/SingleSignOnService", Assert.Single(reader.IdPSsoDescriptor.SingleSignOnServices).Location.AbsolutePath);
            }
            else
            {
                sso = reader.SPSsoDescriptor;
                Assert.Equal("/AssertionConsumerService", Assert.Single(reader.SPSsoDescriptor.AssertionConsumerServices).Location.AbsolutePath);
            }
            Assert.Equal("/SingleLogoutService", Assert.Single(sso.SingleLogoutServices).Location.AbsolutePath);
            Assert.Equal("/ArtifactResolutionService", Assert.Single(sso.ArtifactResolutionServices).Location.AbsolutePath);
            Assert.Equal("urn:test:format", Assert.Single(sso.NameIDFormats).OriginalString);
        }

        [Theory]
        [InlineData(null, true, true)]
        [InlineData("signing", true, false)]
        [InlineData("encryption", false, true)]
        [InlineData("signing-encryption", false, false)]
        [InlineData("", false, false)]
        public void ReadKeys_RequiresQualifiedDescriptorsAndKeyInfoAndExactUse(string? use, bool signing, bool encryption)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=metadata-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            XElement Descriptor(XNamespace descriptorNs, XNamespace keyInfoNs) => new XElement(descriptorNs + "KeyDescriptor",
                use == null ? null : new XAttribute("use", use), new XElement(keyInfoNs + "KeyInfo",
                    new XElement(Ds + "X509Data", new XElement(Ds + "X509Certificate", Convert.ToBase64String(certificate.RawData)))));
            var role = new XElement(Md + "IDPSSODescriptor", Descriptor(Extension, Ds), Descriptor(Md, Extension), Descriptor(Md, Ds));
            var reader = new EntityDescriptor().ReadIdPSsoDescriptor(Entity("partner", role).ToString());

            var thumbprints = new[] { certificate.Thumbprint };
            Assert.Equal(signing ? thumbprints : Array.Empty<string>(), reader.IdPSsoDescriptor.SigningCertificates.Select(c => c.Thumbprint));
            Assert.Equal(encryption ? thumbprints : Array.Empty<string>(), reader.IdPSsoDescriptor.EncryptionCertificates.Select(c => c.Thumbprint));
        }

        private static XElement Entity(string id, params XElement[] children) =>
            new XElement(Md + "EntityDescriptor", new XAttribute("entityID", id), children);

        private static void Read(EntityDescriptor reader, XElement metadata, bool idp)
        {
            if (idp)
            {
                reader.ReadIdPSsoDescriptor(metadata.ToString());
            }
            else
            {
                reader.ReadSPSsoDescriptor(metadata.ToString());
            }
        }
    }
}
