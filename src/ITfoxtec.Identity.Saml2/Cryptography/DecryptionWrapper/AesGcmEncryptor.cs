#if !NETFULL
using System;
using System.Security.Cryptography;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    internal class AesGcmEncryptor : ICryptoTransform
    {
        private readonly byte[] key;
        private readonly byte[] nonce;
        private readonly int authenticationTagSizeInBits;

        public AesGcmEncryptor(byte[] key, byte[] nonce, int authenticationTagSizeInBits)
        {
            this.key = key;
            this.nonce = nonce;
            this.authenticationTagSizeInBits = authenticationTagSizeInBits;
        }

        public bool CanReuseTransform => false;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => 1;

        public int OutputBlockSize => 1;

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var tagSize = authenticationTagSizeInBits / 8;
            var plainBytes = inputBuffer.AsSpan().Slice(inputOffset, inputCount);

            var cipherBytes = new byte[inputCount];
            var tag = new byte[tagSize];

            using (var aesgcm = new AesGcm(key))
            {
                aesgcm.Encrypt(nonce, plainBytes, cipherBytes, tag);
            }

            var result = new byte[inputCount + tagSize];
            Buffer.BlockCopy(cipherBytes, 0, result, 0, cipherBytes.Length);
            Buffer.BlockCopy(tag, 0, result, inputCount, tag.Length);
            return result;
        }
    }
}
#endif
