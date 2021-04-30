using System.Security.Cryptography;
using CryptographyLibrary.Enums;

namespace CryptographyLibrary.AsymmetricEncryption
{
    public class AsymmetricCryptoServiceOptions
    {
        public KeySize KeySize { get; init; } = KeySize.KeySize1024;
        public bool AssignNewKey { get; init; } = true;
        public string XmlPublicKeyFilePath { get; init; }
        public string XmlPrivateKeyFilePath { get; init; }
        public CspParameters CspParameters { get; init; }
    }
}