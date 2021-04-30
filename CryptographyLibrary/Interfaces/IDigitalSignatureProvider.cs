namespace CryptographyLibrary.Interfaces
{
    public interface IDigitalSignatureProvider
    {
        byte[] Sign(byte[] toSign);
        bool Verify(byte[] signature, byte[] toCompare);
    }
}