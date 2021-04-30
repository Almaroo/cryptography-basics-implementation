using System;
using System.Security.Cryptography;
using static CryptographyLibrary.HashData;

namespace CryptographyLibrary
{
    public static class PasswordHash
    {
        private const int SaltLength = 32;
        
        public static byte[] GenerateSalt()
        {
            return Random.GenerateRandomNumber(SaltLength);
        }

        private static byte[] Combine(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

            return ret;
        }

        public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            return CalculateSha256(Combine(toBeHashed, salt));
        }

        public static byte[] HashPasswordPbkdf2(byte[] toBeHashed, byte[] salt, int iterations)
        {
            var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, iterations);
            return rfc2898.GetBytes(20);
        }
    }
}