using System.Security.Cryptography;
using CryptographyLibrary.Interfaces;

namespace CryptographyLibrary.AsymmetricEncryption
{
    internal abstract class AsymmetricCryptoServiceBase: IAsymmetricCryptoService
    {
        protected AsymmetricCryptoServiceOptions Options;

        protected AsymmetricCryptoServiceBase(AsymmetricCryptoServiceOptions options)
        {
            Options = options;
        }

        protected abstract void AssignNewKey();
        public abstract byte[] Encrypt(byte[] toEncrypt);

        public abstract byte[] Decrypt(byte[] toDecrypt);
    }
}