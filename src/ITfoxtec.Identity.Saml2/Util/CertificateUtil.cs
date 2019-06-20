using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Util
{
    public static class CertificateUtil
    {
        public static X509Certificate2 Load(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));

            return new X509Certificate2(path);
        }

        public static X509Certificate2 Load(string path, string password)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

            return new X509Certificate2(path, password);
        }

        public static X509Certificate2 Load(string path, string password, X509KeyStorageFlags keyStorageFlags)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

            return new X509Certificate2(path, password, keyStorageFlags);
        }

        public static X509Certificate2 Load(string path, SecureString password)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
            if (password == null) throw new ArgumentNullException(nameof(password));

            return new X509Certificate2(path, password);
        }

        public static X509Certificate2 Load(string path, SecureString password, X509KeyStorageFlags keyStorageFlags)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
            if (password == null) throw new ArgumentNullException(nameof(password));

            return new X509Certificate2(path, password, keyStorageFlags);
        }

        public static X509Certificate2 LoadBytes(string certificate)
        {
            if (string.IsNullOrWhiteSpace(certificate)) throw new ArgumentNullException(nameof(certificate));

            var encoding = new System.Text.UTF8Encoding();
            return new X509Certificate2(encoding.GetBytes(certificate));
        }

        public static X509Certificate2 LoadBytes(string certificate, string password)
        {
            if (string.IsNullOrWhiteSpace(certificate)) throw new ArgumentNullException(nameof(certificate));
            if (password == null) throw new ArgumentNullException(nameof(password));

            var encoding = new System.Text.UTF8Encoding();
            return new X509Certificate2(encoding.GetBytes(certificate), password);
        }

        public static X509Certificate2 Load(StoreName name, StoreLocation location, X509FindType type, string findValue)
        {
            if (string.IsNullOrWhiteSpace(findValue)) throw new ArgumentNullException(nameof(findValue));

            var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var certificates = store.Certificates.Find(type, findValue, false);

                if (certificates.Count != 1)
                {
                    throw new InvalidOperationException($"Finding certificate with [StoreName: {name}, StoreLocation: {location}, X509FindType: {type}, FindValue: {findValue}] matched {certificates.Count} certificates. A unique match is required.");
                }

                return certificates[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}
