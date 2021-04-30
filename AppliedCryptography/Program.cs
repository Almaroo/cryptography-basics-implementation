using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CryptographyLibrary;
using CryptographyLibrary.AsymmetricEncryption;
using CryptographyLibrary.DigitalSignature;
using CryptographyLibrary.Enums;
using static CryptographyLibrary.Random;
using static CryptographyLibrary.HashData;
using static CryptographyLibrary.SymmetricEncryption;

namespace AppliedCryptography
{
    class Program
    {
        static void Main(string[] args)
        {
            // Test();
        }

        static void Test()
        {
            Console.WriteLine("safe RNG");
            foreach (var i in Enumerable.Range(0,10))
            {
                Console.WriteLine(Convert.ToBase64String(GenerateRandomNumber(32))); ;
            }

            const string message = "Secret message";
            Console.WriteLine($"hashes of '{message}'");
            Console.WriteLine($"MD5: {Convert.ToBase64String(CalculateMd5(Encoding.UTF8.GetBytes(message)))}");
            Console.WriteLine($"SHA1: {Convert.ToBase64String(CalculateSha1(Encoding.UTF8.GetBytes(message)))}");
            Console.WriteLine($"SHA256: {Convert.ToBase64String(CalculateSha256(Encoding.UTF8.GetBytes(message)))}");
            Console.WriteLine($"SHA512: {Convert.ToBase64String(CalculateSha512(Encoding.UTF8.GetBytes(message)))}");
            
            const string message2 = "Secret Message";
            Console.WriteLine($"hashes of '{message2}'");
            Console.WriteLine($"MD5: {Convert.ToBase64String(CalculateMd5(Encoding.UTF8.GetBytes(message2)))}");
            Console.WriteLine($"SHA1: {Convert.ToBase64String(CalculateSha1(Encoding.UTF8.GetBytes(message2)))}");
            Console.WriteLine($"SHA256: {Convert.ToBase64String(CalculateSha256(Encoding.UTF8.GetBytes(message2)))}");
            Console.WriteLine($"SHA512: {Convert.ToBase64String(CalculateSha512(Encoding.UTF8.GetBytes(message2)))}");
            
            Console.WriteLine($"HMACs of '{message}'");
            var key = Hmac.GenerateKey();
            Console.WriteLine($"HmacMd5: {Convert.ToBase64String(Hmac.ComputeHmacMd5(key, Encoding.UTF8.GetBytes(message)))}");
            Console.WriteLine($"HmacSha1: {Convert.ToBase64String(Hmac.ComputeHmacSha1(key, Encoding.UTF8.GetBytes(message)))}");
            Console.WriteLine($"HmacSha256: {Convert.ToBase64String(Hmac.ComputeHmacSha256(key, Encoding.UTF8.GetBytes(message)))}");
            Console.WriteLine($"HmacSha512: {Convert.ToBase64String(Hmac.ComputeHmacSha512(key, Encoding.UTF8.GetBytes(message)))}");

            Console.WriteLine("Hash password with salt");
            const string password = "V3ry1mp0rt4ntP4$$w0rd";
            var salt = PasswordHash.GenerateSalt();
            Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");
            Console.WriteLine(Convert.ToBase64String(PasswordHash.HashPasswordWithSalt(Encoding.UTF8.GetBytes(password), salt)));

            Console.WriteLine("Hash same password with PBKDF2");
            Console.WriteLine(Convert.ToBase64String(PasswordHash.HashPasswordPbkdf2(Encoding.UTF8.GetBytes(password), salt, 150_000)));
            
            Console.WriteLine("DES example on 'Lorem Ipsum'");
            const string messageSymmetric = "Lorem ispum dolor sit amet.";
            var ivDes = GenerateRandomNumber(8);
            var keyDes = GenerateRandomNumber(8);
            var encryptedDes = EncryptDes(Encoding.UTF8.GetBytes(messageSymmetric), keyDes, ivDes);
            var decryptedDes = DecryptDes(encryptedDes, keyDes, ivDes);
            Console.WriteLine($"EncryptedDES: {Convert.ToBase64String(encryptedDes)}");
            Console.WriteLine($"DecryptedDES: {Encoding.UTF8.GetString(decryptedDes)}");

            Console.WriteLine("TripleDES example on Lorem Ipsum");
            var keyTripleDes = GenerateRandomNumber(24);
            var ivTripleDes = GenerateRandomNumber(8);
            var encryptedTripleDes = EncryptTripleDes(Encoding.UTF8.GetBytes(messageSymmetric), keyTripleDes, ivTripleDes);
            var decryptedTripleDes = DecryptTripleDes(encryptedTripleDes, keyTripleDes, ivTripleDes);
            Console.WriteLine($"EncryptedTripleDES: {Convert.ToBase64String(encryptedTripleDes)}");
            Console.WriteLine($"DecryptedTripleDES: {Encoding.UTF8.GetString(decryptedTripleDes)}");

            Console.WriteLine("AES example on Lorem Ipsum");
            var keyAes = GenerateRandomNumber(32);
            var ivAes = GenerateRandomNumber(16);
            var encryptedAes = EncryptAes(Encoding.UTF8.GetBytes(messageSymmetric), keyAes, ivAes);
            var decryptedAes = DecryptAes(encryptedAes, keyAes, ivAes);
            Console.WriteLine($"EncryptedAES: {Convert.ToBase64String(encryptedAes)}");
            Console.WriteLine($"DecryptedAES: {Encoding.UTF8.GetString(decryptedAes)}");

            Console.WriteLine("RSA in memory example on Lorem Ipsum");
            var inMemoryAsymmetricOptions = new AsymmetricCryptoServiceOptions
            {
                KeySize = KeySize.KeySize2048,
            };
            var asymmetricInMemoryCryptoProvider = new AsymmetricCryptoServiceBuilder()
                .WithOptions(inMemoryAsymmetricOptions).WithKeyStorageOption(KeyStorageOption.InMemory).Build();
            var encryptedRsa = asymmetricInMemoryCryptoProvider.Encrypt(Encoding.UTF8.GetBytes(messageSymmetric));
            var decryptedRsa = asymmetricInMemoryCryptoProvider.Decrypt(encryptedRsa);
            Console.WriteLine($"Encrypted RSA: {Convert.ToBase64String(encryptedRsa)}");
            Console.WriteLine($"Decrypted RSA: {Encoding.UTF8.GetString(decryptedRsa)}");
            
            Console.WriteLine("RSA XML example on Lorem Ipsum");
            var xmlAsymmetricOptions = new AsymmetricCryptoServiceOptions
            {
                KeySize = KeySize.KeySize2048,
                XmlPrivateKeyFilePath = Path.Combine(Directory.GetCurrentDirectory(), "privateKey.xml"),
                XmlPublicKeyFilePath = Path.Combine(Directory.GetCurrentDirectory(), "publicKey.xml"),
            };
            var asymmetricXmlCryptoProvider = new AsymmetricCryptoServiceBuilder()
                .WithOptions(xmlAsymmetricOptions).WithKeyStorageOption(KeyStorageOption.InMemory).Build();
            encryptedRsa = asymmetricXmlCryptoProvider.Encrypt(Encoding.UTF8.GetBytes(messageSymmetric));
            decryptedRsa = asymmetricXmlCryptoProvider.Decrypt(encryptedRsa);
            Console.WriteLine($"Encrypted RSA: {Convert.ToBase64String(encryptedRsa)}");
            Console.WriteLine($"Decrypted RSA: {Encoding.UTF8.GetString(decryptedRsa)}");
            
            Console.WriteLine("RSA CSP example on Lorem Ipsum");
            var cspAsymmetricOptions = new AsymmetricCryptoServiceOptions
            {
                CspParameters = new CspParameters(1)
                {
                    KeyContainerName = "AppliedCryptographyTest",
                    ProviderName = "Microsoft Strong Cryptographic Provider",
                    Flags = CspProviderFlags.UseMachineKeyStore,
                },
                KeySize = KeySize.KeySize2048,
            };
            var asymmetricCspCryptoProvider = new AsymmetricCryptoServiceBuilder().WithOptions(cspAsymmetricOptions)
                .WithKeyStorageOption(KeyStorageOption.Csp).Build();
            encryptedRsa = asymmetricCspCryptoProvider.Encrypt(Encoding.UTF8.GetBytes(messageSymmetric));
            decryptedRsa = asymmetricCspCryptoProvider.Decrypt(encryptedRsa);
            Console.WriteLine($"Encrypted RSA: {Convert.ToBase64String(encryptedRsa)}");
            Console.WriteLine($"Decrypted RSA: {Encoding.UTF8.GetString(decryptedRsa)}");

            Console.WriteLine("DigitalSignature InMemory example on LoremIpsum");
            var digitalSignatureInMemoryOptions = new DigitalSignatureProviderOptions
            {
                HashAlgorithm = DigitalSignatureHashAlgorithm.SHA512,
                KeySize = KeySize.KeySize2048,
            };
            var digitalSignatureInMemoryProvider = new DigitalSignatureProviderBuilder()
                .WithOptions(digitalSignatureInMemoryOptions).WithKeyStorageOption(KeyStorageOption.InMemory).Build();
            var signedHash = digitalSignatureInMemoryProvider.Sign(CalculateSha512(Encoding.UTF8.GetBytes(messageSymmetric)));
            Console.WriteLine($"Signed hash: {Convert.ToBase64String(signedHash)}");
            var compareHash = CalculateSha512(Encoding.UTF8.GetBytes(messageSymmetric));
            Console.WriteLine($"Compare hashes: {digitalSignatureInMemoryProvider.Verify(signedHash, compareHash).ToString()}");
            compareHash[0] = Byte.MaxValue;
            Console.WriteLine($"Compare hashes with tapering: {digitalSignatureInMemoryProvider.Verify(signedHash, compareHash).ToString()}");
            
        }
    }
}