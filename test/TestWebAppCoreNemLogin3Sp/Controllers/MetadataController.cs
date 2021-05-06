using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace TestWebApp.Controllers
{
    [AllowAnonymous]
    [Route("Metadata")]
    public class MetadataController : Controller
    {
        private readonly Saml2Configuration config;

        public MetadataController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        public IActionResult Index()
        {
            var defaultSite = new Uri($"{Request.Scheme}://{Request.Host.ToUriComponent()}/");

            var entityDescriptor = new EntityDescriptor(config, signMetadata: false);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor
            {
                WantAssertionsSigned = true,
                SigningCertificates = new X509Certificate2[]
                {
                    config.SigningCertificate
                },
                EncryptionCertificates = new X509Certificate2[]
                {
                    config.DecryptionCertificate
                },
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
            entityDescriptor.ContactPersons = new[] { 
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
            };
            return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
        }

        private IEnumerable<RequestedAttribute> CreateRequestedAttributes()
        {
            yield return new RequestedAttribute("https://data.gov.dk/model/core/specVersion", nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/bootstrapToken", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            //yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/privilegesIntermediate", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/concept/core/nsis/loa", nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/concept/core/nsis/ial", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/concept/core/nsis/aal", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/fullName", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/firstName", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/lastName", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/email", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            //yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/cprNumber", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/age", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/cprUuid", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/dateOfBirth", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/person/pid", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/professional/uuid/persistent", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/professional/rid", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/professional/cvr", nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/professional/orgName", nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/professional/productionUnit", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
            yield return new RequestedAttribute("https://data.gov.dk/model/core/eid/professional/seNumber", isRequired: false, nameFormat: Saml2MetadataConstants.AttributeNameFormatUri);
        }
    }
}