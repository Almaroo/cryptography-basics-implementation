using System.Security.Cryptography;

namespace CryptographyLibrary
{
    public static class HashData
    {
        public static byte[] CalculateMd5(byte[] toBeHashed)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(toBeHashed);
        }

        public static byte[] CalculateSha1(byte[] toBeHashed)
        {
            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(toBeHashed);
        }

        public static byte[] CalculateSha256(byte[] toBeHashed)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(toBeHashed);
        }

        public static byte[] CalculateSha512(byte[] toBeHashed)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(toBeHashed);
        }
    }
}