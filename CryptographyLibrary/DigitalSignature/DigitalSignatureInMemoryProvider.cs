using System.Diagnostics;
using System.Security.Cryptography;
using CryptographyLibrary.AsymmetricEncryption;

namespace CryptographyLibrary.DigitalSignature
{
    internal sealed class DigitalSignatureInMemoryProvider: DigitalSignatureProviderBase
    {
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        
        public DigitalSignatureInMemoryProvider(DigitalSignatureProviderOptions options) : base(options)
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

        public override byte[] Sign(byte[] toSign)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize)
            {
                PersistKeyInCsp = false,
            };
                    
            rsaProvider.ImportParameters(_privateKey);
            var signatureFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
            signatureFormatter.SetHashAlgorithm(Options.HashAlgorithm.ToString());
            return signatureFormatter.CreateSignature(toSign);
        }

        public override bool Verify(byte[] signature, byte[] toCompare)
        {
            using var rsaProvider = new RSACryptoServiceProvider
            {
                PersistKeyInCsp = false,
            };
                    
            rsaProvider.ImportParameters(_publicKey);
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
            rsaDeformatter.SetHashAlgorithm(Options.HashAlgorithm.ToString());
            return rsaDeformatter.VerifySignature(toCompare, signature);
        }
    }
}