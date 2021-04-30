using System;
using CryptographyLibrary.Enums;
using CryptographyLibrary.Interfaces;

namespace CryptographyLibrary.AsymmetricEncryption
{
    public class AsymmetricCryptoServiceBuilder
    {
        public AsymmetricCryptoServiceOptions Options {get; set; }
        public KeyStorageOption KeyStorageOption { get; set; } = KeyStorageOption.InMemory;

        public IAsymmetricCryptoService Build() => KeyStorageOption switch
        {
            KeyStorageOption.Csp => new AsymmetricCspCryptoService(Options),
            KeyStorageOption.Xml => new AsymmetricXmlCryptoService(Options),
            KeyStorageOption.InMemory => new AsymmetricInMemoryCryptoService(Options),
            _ => throw new ArgumentException($"Incorrect value of {nameof(KeyStorageOption)}"),
        };
    }
}