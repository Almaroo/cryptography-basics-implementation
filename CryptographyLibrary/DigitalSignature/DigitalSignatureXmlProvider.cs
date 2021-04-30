using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyLibrary.DigitalSignature
{
    public sealed class DigitalSignatureXmlProvider: DigitalSignatureProviderBase
    {
        public DigitalSignatureXmlProvider(DigitalSignatureProviderOptions options) : base(options)
        {
            if (string.IsNullOrEmpty(Options.XmlPublicKeyFilePath))
            {
                throw new ArgumentException($"{nameof(Options.XmlPublicKeyFilePath)} cannot be null or empty");
            }

            if (string.IsNullOrEmpty(Options.XmlPrivateKeyFilePath))
            {
                throw new ArgumentException($"{nameof(Options.XmlPrivateKeyFilePath)} cannot be null or empty");
            }

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

            File.WriteAllText(Options.XmlPublicKeyFilePath, rsaProvider.ToXmlString(false));
            File.WriteAllText(Options.XmlPrivateKeyFilePath, rsaProvider.ToXmlString(true));
        }

        public override byte[] Sign(byte[] toSign)
        {
            using var rsaProvider = new RSACryptoServiceProvider(4096)
            {
                PersistKeyInCsp = false,
            };
                    
            rsaProvider.FromXmlString(File.ReadAllText(Options.XmlPrivateKeyFilePath));
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
                    
            rsaProvider.FromXmlString(File.ReadAllText(Options.XmlPublicKeyFilePath));
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
            rsaDeformatter.SetHashAlgorithm(Options.HashAlgorithm.ToString());
            return rsaDeformatter.VerifySignature(toCompare, signature);
        }
    }
}