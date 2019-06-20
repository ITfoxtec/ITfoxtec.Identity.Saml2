using ITfoxtec.Identity.Messages;
using Newtonsoft.Json;

namespace TestWebAppCoreAzureKeyVault.AzureKeyVault
{
    public class ADTokenRequest : TokenRequest
    {
        /// <summary>
        /// Azure AD resource.
        /// </summary>
        [JsonProperty(PropertyName = "resource")]
        public string Resource { get; set; }
    }
}
