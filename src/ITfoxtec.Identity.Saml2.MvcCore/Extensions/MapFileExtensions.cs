#if NET || NETCORE
using System;
#endif
using System.IO;
using Microsoft.AspNetCore.Hosting;

namespace ITfoxtec.Identity.Saml2.MvcCore
{
    public static class MapFileExtensions
    {
#if NET || NETCORE
        [Obsolete("The IHostingEnvironment type and this method is obsolete and will be removed in a future version. The recommended alternative is Microsoft.AspNetCore.Hosting.IWebHostEnvironment.", false)]
#endif
        public static string MapToPhysicalFilePath(this IHostingEnvironment appEnvironment, string fileName)
        {
            return Path.Combine(appEnvironment.ContentRootPath, fileName);
        }

#if NET || NETCORE
        public static string MapToPhysicalFilePath(this IWebHostEnvironment appEnvironment, string fileName)
        {
            return Path.Combine(appEnvironment.ContentRootPath, fileName);
        }
#endif
    }
}
