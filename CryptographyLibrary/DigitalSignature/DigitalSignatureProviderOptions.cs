using CryptographyLibrary.AsymmetricEncryption;
using CryptographyLibrary.Enums;

namespace CryptographyLibrary.DigitalSignature
{
    public class DigitalSignatureProviderOptions : AsymmetricCryptoServiceOptions
    {
        public DigitalSignatureHashAlgorithm HashAlgorithm { get; init; } = DigitalSignatureHashAlgorithm.SHA256;
    }
}