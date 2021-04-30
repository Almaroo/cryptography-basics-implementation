using System;
using System.Security.Cryptography;

namespace CryptographyLibrary.AsymmetricEncryption
{
    internal sealed class AsymmetricCspCryptoService: AsymmetricCryptoServiceBase
    {
        public AsymmetricCspCryptoService(AsymmetricCryptoServiceOptions options) : base(options)
        {
            if (options.CspParameters == null)
            {
                throw new ArgumentException($"{nameof(options.CspParameters)} cannot be null or empty");
            }
                
            if (string.IsNullOrEmpty(options.CspParameters.KeyContainerName))
            {
                throw new ArgumentException($"{nameof(options.CspParameters.KeyContainerName)} cannot be null or empty");
            }

            if (Options.AssignNewKey)
            {
                AssignNewKey();
            }
        }
        protected override void AssignNewKey()
        {
            using var rsaProvider = new RSACryptoServiceProvider(Options.CspParameters)
            {
                PersistKeyInCsp = true,
                KeySize = (int)Options.KeySize,
            };
        }

        public override byte[] Encrypt(byte[] toEncrypt)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize, Options.CspParameters);
            return rsaProvider.Encrypt(toEncrypt, true);
        }

        public override byte[] Decrypt(byte[] toDecrypt)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize, Options.CspParameters);
            return rsaProvider.Decrypt(toDecrypt, true);
        }
    }
}