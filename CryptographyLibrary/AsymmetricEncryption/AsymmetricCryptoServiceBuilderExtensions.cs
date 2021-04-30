using CryptographyLibrary.Enums;

namespace CryptographyLibrary.AsymmetricEncryption
{
    public static class AsymmetricCryptoServiceBuilderExtensions
    {
        public static AsymmetricCryptoServiceBuilder WithOptions(this AsymmetricCryptoServiceBuilder builder, AsymmetricCryptoServiceOptions options)
        {
            builder.Options = options;
            return builder;
        }

        public static AsymmetricCryptoServiceBuilder WithKeyStorageOption(this AsymmetricCryptoServiceBuilder builder,
            KeyStorageOption keyStorageOption)
        {
            builder.KeyStorageOption = keyStorageOption;
            return builder;
        }
    }
}