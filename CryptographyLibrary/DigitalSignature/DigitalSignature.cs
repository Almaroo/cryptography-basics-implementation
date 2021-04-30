using System;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using CryptographyLibrary.AsymmetricEncryption;
using CryptographyLibrary.Enums;

namespace CryptographyLibrary.DigitalSignature
{
    public class DigitalSignature
    {
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        private const string containerName = "Digital Signature container";

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

        public byte[] SignData(byte[] toBeSigned, KeyStorageOption keyStorageOption, string privateKeyFilePath = "")
        {
            var signedBytes = Array.Empty<byte>();
            
            switch (keyStorageOption)
            {
                case KeyStorageOption.InMemory:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };
                    
                    rsaProvider.ImportParameters(_privateKey);
                    var signatureFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
                    signatureFormatter.SetHashAlgorithm("SHA512");
                    signedBytes = signatureFormatter.CreateSignature(toBeSigned);
                    break;
                }
                case KeyStorageOption.Xml:
                {
                    using var rsaProvider = new RSACryptoServiceProvider(4096)
                    {
                        PersistKeyInCsp = false,
                    };
                    
                    rsaProvider.FromXmlString(File.ReadAllText(privateKeyFilePath));
                    var signatureFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
                    signatureFormatter.SetHashAlgorithm("SHA512");
                    signedBytes = signatureFormatter.CreateSignature(toBeSigned);
                    break;
                }
                case KeyStorageOption.Csp:
                {
                    var cspParameters = new CspParameters
                    {
                        KeyContainerName = containerName,
                    };
                    
                    using var rsaProvider = new RSACryptoServiceProvider(4096, cspParameters)
                    {
                        PersistKeyInCsp = true,
                    };
                    var signatureFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
                    signatureFormatter.SetHashAlgorithm("SHA512");
                    signedBytes = signatureFormatter.CreateSignature(toBeSigned);
                    break;
                }
            }

            return signedBytes;
        }

        public bool VerifySignature(byte[] hashToSign, byte[] signature, KeyStorageOption keyStorageOption,
            string publicKeyFilePath = "")
        {
            bool isValid = default;
            switch (keyStorageOption)
            {
                case KeyStorageOption.InMemory:
                {
                    using var rsaProvider = new RSACryptoServiceProvider
                    {
                        PersistKeyInCsp = false,
                    };
                    
                    rsaProvider.ImportParameters(_publicKey);
                    var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
                    rsaDeformatter.SetHashAlgorithm("SHA512");
                    isValid = rsaDeformatter.VerifySignature(hashToSign, signature);
                    break;
                }
                case KeyStorageOption.Xml:
                {
                    using var rsaProvider = new RSACryptoServiceProvider
                    {
                        PersistKeyInCsp = false,
                    };
                    
                    rsaProvider.FromXmlString(File.ReadAllText(publicKeyFilePath));
                    var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
                    rsaDeformatter.SetHashAlgorithm("SHA512");
                    isValid = rsaDeformatter.VerifySignature(hashToSign, signature);
                    break;
                }
                case KeyStorageOption.Csp:
                {
                    var cspParameters = new CspParameters
                    {
                        KeyContainerName = containerName,
                    };

                    using var rsaProvider = new RSACryptoServiceProvider(4096, cspParameters)
                    {
                        PersistKeyInCsp = true,
                    };
                    var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
                    rsaDeformatter.SetHashAlgorithm("SHA512");
                    isValid = rsaDeformatter.VerifySignature(hashToSign, signature);
                    break;
                }
            }

            return isValid;
        }
    }
}