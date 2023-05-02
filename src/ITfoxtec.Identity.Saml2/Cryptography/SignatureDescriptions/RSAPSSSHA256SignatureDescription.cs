using System.Security.Cryptography;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class RSAPSSSHA256SignatureDescription : SignatureDescription
    {
        public RSAPSSSHA256SignatureDescription()
        {
            using (var rsa = RSA.Create())
            {
                this.KeyAlgorithm = rsa.GetType().AssemblyQualifiedName; // Does not like a simple algorithm name, but wants a type name (AssembyQualifiedName in Core)
            }
           
            this.DigestAlgorithm = "SHA256"; // Somehow wants a simple algorithm name
            this.FormatterAlgorithm = typeof(RsaPssSignatureFormatter).FullName;
            this.DeformatterAlgorithm = typeof(RsaPssSignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            var signatureFormatter = new RsaPssSignatureFormatter();
            signatureFormatter.SetKey(key);
            signatureFormatter.SetHashAlgorithm(this.DigestAlgorithm);
            return signatureFormatter;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            var signatureDeformatter = new RsaPssSignatureDeformatter();
            signatureDeformatter.SetKey(key);
            signatureDeformatter.SetHashAlgorithm(this.DigestAlgorithm);
            return signatureDeformatter;
        }

        public class RsaPssSignatureFormatter : AsymmetricSignatureFormatter
        {
            private RSA Key { get; set; }
            private string HashAlgorithmName { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                this.Key = (RSA)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                // Verify the name
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);

                this.HashAlgorithmName = strName;
            }

            public override byte[] CreateSignature(byte[] rgbHash)
            {
                return this.Key.SignHash(rgbHash, new HashAlgorithmName(this.HashAlgorithmName), RSASignaturePadding.Pss);
            }
        }

        public class RsaPssSignatureDeformatter : AsymmetricSignatureDeformatter
        {
            private RSA Key { get; set; }
            private string HashAlgorithmName { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                this.Key = (RSA)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                // Verify the name
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);

                this.HashAlgorithmName = strName;
            }
            
            public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
            {
                return this.Key.VerifyHash(rgbHash, rgbSignature, new HashAlgorithmName(this.HashAlgorithmName), RSASignaturePadding.Pss);
            }
        }
    }
}
