using System.IO;
using Microsoft.AspNetCore.Hosting;

namespace ITfoxtec.Identity.Saml2.MvcCore
{
    public static class MapFileExtensions
    {
        public static string MapToPhysicalFilePath(this IHostingEnvironment appEnvironment, string fileName)
        {
            return Path.Combine(appEnvironment.ContentRootPath, fileName);
        }
    }
}
