namespace CryptoUtility;

public interface IPasswordKdf
{
    public byte[] DeriveKey(string password, byte[] salt, int iterations, int outputLength);
}
