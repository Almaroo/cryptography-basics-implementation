using System.Security.Cryptography;
using static CryptographyLibrary.Random;

namespace CryptographyLibrary
{
    public static class Hmac
    {
        private const int KeySize = 32;

        public static byte[] GenerateKey()
        {
            return GenerateRandomNumber(32);
        }

        public static byte[] ComputeHmacSha256(byte[] key, byte[] toBeHashed)
        {
            using var hmacSha256 = new HMACSHA256(key);
            return hmacSha256.ComputeHash(toBeHashed);
        }
        
        public static byte[] ComputeHmacSha512(byte[] key, byte[] toBeHashed)
        {
            using var hmacSha512 = new HMACSHA512(key);
            return hmacSha512.ComputeHash(toBeHashed);
        }
        
        public static byte[] ComputeHmacSha1(byte[] key, byte[] toBeHashed)
        {
            using var hmacSha1 = new HMACSHA1(key);
            return hmacSha1.ComputeHash(toBeHashed);
        }
        
        public static byte[] ComputeHmacMd5(byte[] key, byte[] toBeHashed)
        {
            using var hmacMd5 = new HMACMD5(key);
            return hmacMd5.ComputeHash(toBeHashed);
        }
    }
}