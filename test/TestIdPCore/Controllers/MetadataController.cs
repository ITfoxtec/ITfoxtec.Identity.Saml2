using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;

namespace TestWebApp.Controllers
{
    [AllowAnonymous]
    [Route("Metadata")]
    public class MetadataController : Controller
    {
        private readonly Saml2Configuration config;

        public MetadataController(Saml2Configuration config)
        {
            this.config = config;
        }

        public IActionResult Index()
        {
            var entityDescriptor = new EntityDescriptor(config);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.IdPSsoDescriptor = new IdPSsoDescriptor
            {
                WantAuthnRequestsSigned = config.SignAuthnRequest,
                SigningCertificates =
                [
                    config.SigningCertificate
                ],
                //EncryptionCertificates = config.DecryptionCertificates,
                SingleSignOnServices =
                [
                    new SingleSignOnService { Binding = ProtocolBindings.HttpRedirect, Location = config.SingleSignOnDestination }
                ],
                SingleLogoutServices =
                [
                    new SingleLogoutService { Binding = ProtocolBindings.HttpPost, Location = config.SingleLogoutDestination }
                ],
                ArtifactResolutionServices =
                [
                    new ArtifactResolutionService { Binding = ProtocolBindings.ArtifactSoap, Index = config.ArtifactResolutionService.Index, Location = config.ArtifactResolutionService.Location }
                ],
                NameIDFormats = [NameIdentifierFormats.X509SubjectName],
                Attributes =
                [
                    new SamlAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendlyName: "eduPersonPrincipalName"), 
                    new SamlAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.1", new string[] { "member", "student", "employee" }) 
                ]
            };
            var organization = new Organization(
                [new LocalizedNameType("Some Organization", "en")],
                [new LocalizedNameType("Some Organization Display Name", "en")],
                [new LocalizedUriType(new Uri("http://some-organization.com"), "en")]);
        
            entityDescriptor.Organization = organization;
            entityDescriptor.ContactPersons = 
            [
                new ContactPerson(ContactTypes.Administrative)
                {
                    Company = "Some Company",
                    GivenName = "Some Given Name",
                    SurName = "Some Sur Name",
                    EmailAddress = "some@some-domain.com",
                    TelephoneNumber = "11111111",
                },
                new ContactPerson(ContactTypes.Technical)
                {
                    Company = "Some Company",
                    GivenName = "Some tech Given Name",
                    SurName = "Some tech Sur Name",
                    EmailAddress = "sometech@some-domain.com",
                    TelephoneNumber = "22222222",
                }
            ];
            return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
        }
    }
}