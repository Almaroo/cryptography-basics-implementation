using System;
using System.IO;
using System.Security.Cryptography;
using CryptographyLibrary.AsymmetricEncryption;

namespace CryptographyLibrary.AsymmetricEncryption
{
    internal sealed class AsymmetricXmlCryptoService: AsymmetricCryptoServiceBase
    {
        public AsymmetricXmlCryptoService(AsymmetricCryptoServiceOptions options) : base(options)
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

        public override byte[] Encrypt(byte[] toEncrypt)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize)
            {
                PersistKeyInCsp = false,
            };
                    
            rsaProvider.FromXmlString(File.ReadAllText(Options.XmlPublicKeyFilePath));
            return rsaProvider.Encrypt(toEncrypt, true);
        }

        public override byte[] Decrypt(byte[] toDecrypt)
        {
            using var rsaProvider = new RSACryptoServiceProvider((int)Options.KeySize)
            {
                PersistKeyInCsp = false,
            };
                    
            rsaProvider.FromXmlString(File.ReadAllText(Options.XmlPrivateKeyFilePath));
            return rsaProvider.Decrypt(toDecrypt, true);
        }
    }
}