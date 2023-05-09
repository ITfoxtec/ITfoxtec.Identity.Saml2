using System;
using System.Security.Cryptography;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class RSAPSSSHA256SignatureDescription : SignatureDescription
    {
        public RSAPSSSHA256SignatureDescription()
        {
            KeyAlgorithm = typeof(RSACryptoServiceProvider).AssemblyQualifiedName;
            DigestAlgorithm = "SHA256"; 
            FormatterAlgorithm = typeof(RsaPssSignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(RsaPssSignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            var signatureFormatter = new RsaPssSignatureFormatter();
            signatureFormatter.SetKey(key);
            signatureFormatter.SetHashAlgorithm(DigestAlgorithm);
            return signatureFormatter;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            var signatureDeformatter = new RsaPssSignatureDeformatter();
            signatureDeformatter.SetKey(key);
            signatureDeformatter.SetHashAlgorithm(DigestAlgorithm);
            return signatureDeformatter;
        }

        public class RsaPssSignatureFormatter : AsymmetricSignatureFormatter
        {
            private RSA Key { get; set; }
            private string HashAlgorithmName { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                Key = (RSA)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                // Verify the name
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);

                HashAlgorithmName = strName;
            }

            public override byte[] CreateSignature(byte[] rgbHash)
            {
                return Key.SignHash(rgbHash, new HashAlgorithmName(HashAlgorithmName), RSASignaturePadding.Pss);
            }
        }

        public class RsaPssSignatureDeformatter : AsymmetricSignatureDeformatter
        {
            private RSA Key { get; set; }
            private string HashAlgorithmName { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                Key = (RSA)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                // Verify the name
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);

                HashAlgorithmName = strName;
            }
            
            public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
            {
                return Key.VerifyHash(rgbHash, rgbSignature, new HashAlgorithmName(HashAlgorithmName), RSASignaturePadding.Pss);
            }
        }
    }
}
