using System;
using ITfoxtec.Identity.Helpers;
using Microsoft.Azure.KeyVault;

namespace TestWebAppCoreAzureKeyVault.AzureKeyVault
{
    public static class AppKeyVaultClient
    {
        public static KeyVaultClient GetClient(string keyVaultClientId, string keyVaultClientSecret, TokenHelper tokenHelper)
        {
            var client = new KeyVaultClient(async (authority, resource, scope) =>
            {
                try
                {
                    var tokenRequest = new ADTokenRequest
                    {
                        Resource = resource
                    };
                    return await tokenHelper.GetAccessTokenWithClientCredentialsAsync(keyVaultClientId, keyVaultClientSecret, $"{authority}/oauth2/token", tokenRequest);
                }
                catch (Exception ex)
                {
                    throw new Exception("Error while retrieving a token from Azure AD to Azure Key Vault.", ex);
                }
            });

            return client;
        }
    }
}
