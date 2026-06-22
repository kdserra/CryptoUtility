namespace CryptoUtility;

public interface IPasswordKdf
{
    public byte[] DeriveKey(string passwordUtf8, byte[] salt, int iterations, int outputLength);
}
