using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using TestWebAppCoreNemLogin3Sp.Identity;

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
            var defaultSite = new Uri($"{Request.Scheme}://{Request.Host.ToUriComponent()}/");

            var entityDescriptor = new EntityDescriptor(config, signMetadata: false);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor
            {
                SigningCertificates = new X509Certificate2[]
                {
                    config.SigningCertificate
                },
                EncryptionCertificates = config.DecryptionCertificates,
                SingleLogoutServices = new SingleLogoutService[]
                {
                    new SingleLogoutService { Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "Auth/SingleLogout"), ResponseLocation = new Uri(defaultSite, "Auth/LoggedOut") }
                },
                NameIDFormats = new Uri[] { NameIdentifierFormats.Persistent },
                AssertionConsumerServices = new AssertionConsumerService[]
                {
                    new AssertionConsumerService { Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "Auth/AssertionConsumerService") }
                },
                AttributeConsumingServices = new AttributeConsumingService[]
                {
                    new AttributeConsumingService { ServiceName = new ServiceName("ITfoxtecIdentitySaml2-dev", "en"), RequestedAttributes = CreateRequestedAttributes() }
                },
            };
            entityDescriptor.SPSsoDescriptor.SetDefaultEncryptionMethods();
            entityDescriptor.ContactPersons = new[] { 
                new ContactPerson(ContactTypes.Administrative)
                {
                    Company = "Some Company",
                    GivenName = "Some Given Name",
                    SurName = "Some Surname",
                    EmailAddress = "some@some-domain.com",
                    TelephoneNumber = "11111111",
                },
                new ContactPerson(ContactTypes.Technical)
                {
                    Company = "Some Company",
                    GivenName = "Some tech Given Name",
                    SurName = "Some tech Surname",
                    EmailAddress = "sometech@some-domain.com",
                    TelephoneNumber = "22222222",
                }
            };
            return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
        }

        private IEnumerable<RequestedAttribute> CreateRequestedAttributes()
        {
            yield return new RequestedAttribute(OioSaml3ClaimTypes.SpecVersion, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.BootstrapToken, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            //yield return new RequestedAttribute(OioSaml3ClaimTypes.PrivilegesIntermediate, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);

            yield return new RequestedAttribute(OioSaml3ClaimTypes.NsisLoa, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.NsisIal, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.NsisAal, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);

            yield return new RequestedAttribute(OioSaml3ClaimTypes.FullName, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.FirstName, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.LastName, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.Email, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            // CPR number is only applicable in for a Public IT system and not a Private IT system in NemLog-in3
            yield return new RequestedAttribute(OioSaml3ClaimTypes.CprNumber, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.Age, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.CprUuid, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.DateOfBirth, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);

            yield return new RequestedAttribute(OioSaml3ClaimTypes.PersonPid, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);

            yield return new RequestedAttribute(OioSaml3ClaimTypes.ProfessionalUuidPersistent, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.ProfessionalRid, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.ProfessionalCvr, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.ProfessionalOrgName, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.ProfessionalProductionUnit, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute(OioSaml3ClaimTypes.ProfessionalSeNumber, isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
        }
    }
}