using System;
using System.Security.Cryptography;

namespace CryptographyLibrary.DigitalSignature
{
    internal sealed class DigitalSignatureCspProvider: DigitalSignatureProviderBase
    {
        public DigitalSignatureCspProvider(DigitalSignatureProviderOptions options) : base(options)
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

        public override byte[] Sign(byte[] toSign)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize, Options.CspParameters)
            {
                PersistKeyInCsp = true,
            };
            var signatureFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
            signatureFormatter.SetHashAlgorithm(Options.HashAlgorithm.ToString());
            return signatureFormatter.CreateSignature(toSign);
        }

        public override bool Verify(byte[] signature, byte[] toCompare)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize, Options.CspParameters)
            {
                PersistKeyInCsp = true,
            };
            
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
            rsaDeformatter.SetHashAlgorithm(Options.HashAlgorithm.ToString());
            return rsaDeformatter.VerifySignature(toCompare, signature);
        }
    }
}