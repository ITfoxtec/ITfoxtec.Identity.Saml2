#if !NETFULL
using System;
using System.Security.Cryptography;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    /// <summary>
    /// SymmetricAlgorithm decrypting implementation for http://www.w3.org/2009/xmlenc11#aes128-gcm and http://www.w3.org/2009/xmlenc11#aes256-gcm.
    /// This is class is not a general implementation and can only do decryption.
    /// </summary>
    public class AesGcmAlgorithm : SymmetricAlgorithm
    {
        public const string AesGcm128Identifier = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
        public const string AesGcm192Identifier = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
        public const string AesGcm256Identifier = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

        // "For the purposes of this specification, AES-GCM shall be used with a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T)."
        // Source: https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
        public const int NonceSizeInBits = 96;
        private const int AuthenticationTagSizeInBits = 128;

        public AesGcmAlgorithm()
        {
            LegalKeySizesValue = new[] {
                new KeySizes(128, 256, 64),
            };

            //iv setter checks that iv is the size of a block. Not sure if there should be other block sizes
            LegalBlockSizesValue = new[] { new KeySizes(NonceSizeInBits, NonceSizeInBits, 0) };
            BlockSizeValue = NonceSizeInBits;
            KeySizeValue = 256;
            //dummy iv value since it is accessed first in EncryptedXml.DecryptData
            IV = new byte[NonceSizeInBits / 8];
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new AesGcmDecryptor(rgbKey, rgbIV, AuthenticationTagSizeInBits);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new AesGcmEncryptor(rgbKey, rgbIV, AuthenticationTagSizeInBits);
        }

        public override void GenerateIV()
        {
            IV = GenerateRandomBytes(NonceSizeInBits / 8);
        }

        public override void GenerateKey()
        {
            Key = GenerateRandomBytes(KeySize / 8);
        }

        private static byte[] GenerateRandomBytes(int count)
        {
            var bytes = new byte[count];
            using (var randomNumberGenerator = RandomNumberGenerator.Create())
            {
                randomNumberGenerator.GetBytes(bytes);
            }
            return bytes;
        }
    }
}
#endif
