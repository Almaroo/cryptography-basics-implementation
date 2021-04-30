namespace CryptographyLibrary.Interfaces
{
    public interface IAsymmetricCryptoService
    {
        byte[] Encrypt(byte[] toEncrypt);
        byte[] Decrypt(byte[] toDecrypt);
    }
}