using System.Security.Cryptography;

namespace CryptographyLibrary
{
    public static class Random
    {
        public static byte[] GenerateRandomNumber(int length)
        {
            using var randomNumberGenerator = new RNGCryptoServiceProvider();
            var randomNumber = new byte[length];
            randomNumberGenerator.GetBytes(randomNumber);
            return randomNumber;
        }
    }
}