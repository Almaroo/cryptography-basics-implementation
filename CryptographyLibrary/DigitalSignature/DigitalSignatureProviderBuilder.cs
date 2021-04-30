using System;
using CryptographyLibrary.AsymmetricEncryption;
using CryptographyLibrary.Enums;
using CryptographyLibrary.Interfaces;

namespace CryptographyLibrary.DigitalSignature
{
    public class DigitalSignatureProviderBuilder
    {
       public DigitalSignatureProviderOptions Options { get; set; }
       public KeyStorageOption KeyStorageOption { get; set; } = KeyStorageOption.InMemory;

       public IDigitalSignatureProvider Build() => KeyStorageOption switch
       {
           KeyStorageOption.InMemory => new DigitalSignatureInMemoryProvider(Options),
           KeyStorageOption.Xml => new DigitalSignatureXmlProvider(Options),
           KeyStorageOption.Csp => new DigitalSignatureCspProvider(Options),
           _ => throw new ArgumentException($"Incorrect value of {nameof(KeyStorageOption)}"),
       };
    }
}