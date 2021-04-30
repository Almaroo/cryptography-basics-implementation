using CryptographyLibrary.Enums;

namespace CryptographyLibrary.DigitalSignature
{
    public static class DigitalSignatureServiceBuilderExtensions
    {
        public static DigitalSignatureProviderBuilder WithOptions(this DigitalSignatureProviderBuilder builder,
            DigitalSignatureProviderOptions options)
        {
            builder.Options = options;
            return builder;
        }

        public static DigitalSignatureProviderBuilder WithKeyStorageOption(this DigitalSignatureProviderBuilder builder,
            KeyStorageOption keyStorageOption)
        {
            builder.KeyStorageOption = keyStorageOption;
            return builder;
        }
    }
}