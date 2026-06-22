#if NET && !NET70 && !NET60
using System;
using System.Security.Cryptography;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public abstract class ECDSASignatureDescription : SignatureDescription
    {
        protected ECDSASignatureDescription(string digestAlgorithm)
        {
            KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
            DigestAlgorithm = digestAlgorithm;
            FormatterAlgorithm = typeof(ECDSASignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(ECDSASignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var formatter = new ECDSASignatureFormatter();
            formatter.SetKey(key);
            formatter.SetHashAlgorithm(DigestAlgorithm);
            return formatter;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var deformatter = new ECDSASignatureDeformatter();
            deformatter.SetKey(key);
            deformatter.SetHashAlgorithm(DigestAlgorithm);
            return deformatter;
        }

        public class ECDSASignatureFormatter : AsymmetricSignatureFormatter
        {
            private ECDsa Key { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                Key = (ECDsa)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);
            }

            public override byte[] CreateSignature(byte[] rgbHash)
            {
                return Key.SignHash(rgbHash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }

        public class ECDSASignatureDeformatter : AsymmetricSignatureDeformatter
        {
            private ECDsa Key { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                Key = (ECDsa)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);
            }

            public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
            {
                return Key.VerifyHash(rgbHash, rgbSignature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }
    }
}
#endif
