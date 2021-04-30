using System.Security.Cryptography;

namespace CryptographyLibrary.AsymmetricEncryption
{
    internal sealed class AsymmetricInMemoryCryptoService: AsymmetricCryptoServiceBase
    {
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        
        public AsymmetricInMemoryCryptoService(AsymmetricCryptoServiceOptions options) : base(options)
        {
            if (Options.AssignNewKey)
            {
                AssignNewKey();
            }
        }

        protected override void AssignNewKey()
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize)
            {
                PersistKeyInCsp = false,
            };

            _publicKey = rsaProvider.ExportParameters(false);
            _privateKey = rsaProvider.ExportParameters(true);
        }

        public override byte[] Encrypt(byte[] toEncrypt)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize)
            {
                PersistKeyInCsp = false,
            };
                    
            rsaProvider.ImportParameters(_publicKey);

            return rsaProvider.Encrypt(toEncrypt, true);
        }

        public override byte[] Decrypt(byte[] toDecrypt)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize)
            {
                PersistKeyInCsp = false,
            };

            rsaProvider.ImportParameters(_privateKey);

            return rsaProvider.Decrypt(toDecrypt, true);
        }
    }
}