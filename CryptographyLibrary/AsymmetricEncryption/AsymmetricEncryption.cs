using System;
using System.IO;
using System.Security.Cryptography;
using CryptographyLibrary.Enums;

namespace CryptographyLibrary.AsymmetricEncryption
{
    internal class AsymmetricEncryption
    {
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        private const string containerName = "Test container";

        public void AssignNewKey(KeyStorageOption keyStorageOption, string publicKeyFilePath = "",
            string privateKeyFilePath = "")
        {
            switch (keyStorageOption)
            {
                case KeyStorageOption.InMemory:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };

                    _publicKey = rsaProvider.ExportParameters(false);
                    _privateKey = rsaProvider.ExportParameters(true);
                    break;
                }
                case KeyStorageOption.Xml:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };

                    File.WriteAllText(publicKeyFilePath, rsaProvider.ToXmlString(false));
                    File.WriteAllText(privateKeyFilePath, rsaProvider.ToXmlString(true));
                    break;
                }
                case KeyStorageOption.Csp:
                {
                    var cspParameters = new CspParameters(1)
                    {
                        ProviderName = "Microsoft Strong Cryptographic Provider",
                        KeyContainerName = containerName,
                        Flags = CspProviderFlags.UseMachineKeyStore,
                    };

                    using var rsaProvider = new RSACryptoServiceProvider(cspParameters)
                    {
                        PersistKeyInCsp = true,
                        KeySize = 4096,
                    };
                    break;
                }
            }
        }

        public void DeleteKeyInCsp()
        {
            var cspParameters = new CspParameters
            {
                KeyContainerName = containerName,
            };
            
            using var rsaProvider = new RSACryptoServiceProvider(cspParameters)
            {
                PersistKeyInCsp = false,
            };
            
            rsaProvider.Clear();
        }

        public byte[] EncryptData(byte[] toBeEncrypted, KeyStorageOption keyStorageOption, string publicKeyFilePath = "")
        {
            var cipherBytes = Array.Empty<byte>();
            switch (keyStorageOption)
            {
                case KeyStorageOption.InMemory:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };
                    
                    rsaProvider.ImportParameters(_publicKey);

                    cipherBytes = rsaProvider.Encrypt(toBeEncrypted, true);
                    break;
                }
                case KeyStorageOption.Xml:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };
                    
                    rsaProvider.FromXmlString(File.ReadAllText(publicKeyFilePath));
                    cipherBytes = rsaProvider.Encrypt(toBeEncrypted, true);
                    break;
                }
                case KeyStorageOption.Csp:
                {
                    var cspParameters = new CspParameters
                    {
                        KeyContainerName = containerName,
                    };
                    
                    using var rsaProvider = new RSACryptoServiceProvider(4096, cspParameters);
                    cipherBytes = rsaProvider.Encrypt(toBeEncrypted, true);
                    break;
                }
            }

            return cipherBytes;
        }

        public byte[] DecryptData(byte[] toBeDecrypted, KeyStorageOption keyStorageOption, string privateKeyFilePath = "")
        {
            var cipherBytes = Array.Empty<byte>();
            switch (keyStorageOption)
            {
                case KeyStorageOption.InMemory:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };

                    rsaProvider.ImportParameters(_privateKey);

                    cipherBytes = rsaProvider.Decrypt(toBeDecrypted, true);
                    break;
                }
                case KeyStorageOption.Xml:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };
                    
                    rsaProvider.FromXmlString(File.ReadAllText(privateKeyFilePath));
                    cipherBytes = rsaProvider.Decrypt(toBeDecrypted, true);
                    break;
                }
                case KeyStorageOption.Csp:
                {
                    var cspParameters = new CspParameters
                    {
                        KeyContainerName = containerName,
                    };
                    
                    using var rsaProvider = new RSACryptoServiceProvider(4096, cspParameters);
                    cipherBytes = rsaProvider.Decrypt(toBeDecrypted, true);
                    break;
                }
            }

            return cipherBytes;
        }
    }
}