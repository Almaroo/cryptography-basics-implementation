using System.IO;
using System.Security.Cryptography;

namespace CryptographyLibrary
{
    public static class SymmetricEncryption
    {
        public static byte[] EncryptDes(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            using var des = new DESCryptoServiceProvider
            {
                Mode = CipherMode.CBC, Key = key, Padding = PaddingMode.PKCS7, IV = iv,
            };
            
            using var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(toBeEncrypted, 0, toBeEncrypted.Length);
            cryptoStream.FlushFinalBlock();
            return memoryStream.ToArray();
        }

        public static byte[] DecryptDes(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            using var des = new DESCryptoServiceProvider
            {
                Mode = CipherMode.CBC, Key = key, Padding = PaddingMode.PKCS7, IV = iv,
            };
            
            using var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(toBeDecrypted, 0, toBeDecrypted.Length);
            cryptoStream.FlushFinalBlock();
            return memoryStream.ToArray();
        }
        
        public static byte[] EncryptTripleDes(byte[] toBeEncrypted, byte[] key, byte[] iv)
         {
             using var des = new TripleDESCryptoServiceProvider
             {
                 Mode = CipherMode.CBC, Key = key, Padding = PaddingMode.PKCS7, IV = iv,
             };
             
             using var memoryStream = new MemoryStream();
             var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(), CryptoStreamMode.Write);
             cryptoStream.Write(toBeEncrypted, 0, toBeEncrypted.Length);
             cryptoStream.FlushFinalBlock();
             return memoryStream.ToArray();
         }

        public static byte[] DecryptTripleDes(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            using var des = new TripleDESCryptoServiceProvider
            {
                Mode = CipherMode.CBC, Key = key, Padding = PaddingMode.PKCS7, IV = iv,
            };
            
            using var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(toBeDecrypted, 0, toBeDecrypted.Length);
            cryptoStream.FlushFinalBlock();
            return memoryStream.ToArray();
        }
        
        public static byte[] EncryptAes(byte[] toBeEncrypted, byte[] key, byte[] iv)
        {
            using var aes = new AesCryptoServiceProvider
            {
                Mode = CipherMode.CBC, Key = key, Padding = PaddingMode.PKCS7, IV = iv,
            };
            
            using var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(toBeEncrypted, 0, toBeEncrypted.Length);
            cryptoStream.FlushFinalBlock();
            return memoryStream.ToArray();
        }

        public static byte[] DecryptAes(byte[] toBeDecrypted, byte[] key, byte[] iv)
        {
            using var aes = new AesCryptoServiceProvider
            {
                Mode = CipherMode.CBC, Key = key, Padding = PaddingMode.PKCS7, IV = iv,
            };
            
            using var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(toBeDecrypted, 0, toBeDecrypted.Length);
            cryptoStream.FlushFinalBlock();
            return memoryStream.ToArray();
        }
        
    }
}